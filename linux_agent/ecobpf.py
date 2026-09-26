import time
import os
import glob
import threading
import argparse
import asyncio
import yaml
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from bcc import BPF

# Load Config
parser = argparse.ArgumentParser()
parser.add_argument("-c", "--config", default="config.yaml", help="Path to config file")
args, unknown = parser.parse_known_args()

with open(args.config, "r") as f:
    config = yaml.safe_load(f)

BINARY_PATH = config.get("target_binary", "/usr/bin/redis-server")
FUNCTIONS = config.get("functions", [])
HOST = config.get("host", "0.0.0.0")
PORT = config.get("port", 8000)
AI_API_KEY = config.get("ai_api_key", "")

# ---------------------------------------------------------
# BPF PROGRAM GENERATION
# ---------------------------------------------------------

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct func_stats {
    u64 duration_ns;
    u64 calls;
};

// Map to store entry timestamp per thread for a specific function id
// Key: pid_tgid ^ (func_id << 32), Value: timestamp
BPF_HASH(entry_time, u64, u64);

// Map to store aggregated stats per function
// Key: function index (u32), Value: func_stats
BPF_ARRAY(stats, struct func_stats, NUM_FUNCTIONS);

static inline int trace_entry(struct pt_regs *ctx, u32 func_id) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    u64 key = pid_tgid ^ ((u64)func_id << 32);
    entry_time.update(&key, &ts);
    return 0;
}

static inline int trace_return(struct pt_regs *ctx, u32 func_id) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 key = pid_tgid ^ ((u64)func_id << 32);
    u64 *tsp = entry_time.lookup(&key);
    
    if (tsp == 0) {
        return 0; // missed entry
    }
    
    u64 delta = bpf_ktime_get_ns() - *tsp;
    entry_time.delete(&key);
    
    u32 index = func_id;
    struct func_stats *st = stats.lookup(&index);
    if (st) {
        __sync_fetch_and_add(&st->duration_ns, delta);
        __sync_fetch_and_add(&st->calls, 1);
    }
    return 0;
}
"""

bpf_text = bpf_text.replace("NUM_FUNCTIONS", str(len(FUNCTIONS)))

for i, func in enumerate(FUNCTIONS):
    bpf_text += f"""
int trace_entry_{i}(struct pt_regs *ctx) {{
    return trace_entry(ctx, {i});
}}
int trace_return_{i}(struct pt_regs *ctx) {{
    return trace_return(ctx, {i});
}}
"""

print(f"Compiling eBPF program for {len(FUNCTIONS)} functions...")
try:
    bpf = BPF(text=bpf_text)
except Exception as e:
    print(f"Failed to compile BPF program. Are you running as root? Error: {e}")
    exit(1)

# Attach probes
for i, func in enumerate(FUNCTIONS):
    try:
        bpf.attach_uprobe(name=BINARY_PATH, sym=func, fn_name=f"trace_entry_{i}")
        bpf.attach_uretprobe(name=BINARY_PATH, sym=func, fn_name=f"trace_return_{i}")
        print(f"Attached probes to {func}")
    except Exception as e:
        print(f"Failed to attach to {func}: {e}")

# ---------------------------------------------------------
# RAPL READER & ATTRIBUTION
# ---------------------------------------------------------
class TelemetryData:
    def __init__(self):
        self.lock = threading.Lock()
        self.total_power_w = 0.0
        self.total_energy_mj = 0.0
        
        self.functions_data = {func: {"energy_mJ": 0.0, "cycle_share": 0.0, "calls": 0, "duration_ns": 0} for func in FUNCTIONS}
        
        paths = glob.glob("/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj")
        if not paths:
            print("WARNING: RAPL energy file not found. Ensure you are on an Intel/AMD CPU with RAPL enabled.")
            self.rapl_path = None
            self.last_rapl_energy_uj = 0
        else:
            self.rapl_path = paths[0]
            with open(self.rapl_path, "r") as f:
                self.last_rapl_energy_uj = int(f.read().strip())
                
        self.last_time_ns = time.time_ns()

telemetry = TelemetryData()

def read_rapl_uj():
    if not telemetry.rapl_path:
        # Dummy data for testing if RAPL is missing (Simulates ~15W)
        return telemetry.last_rapl_energy_uj + 1500000 
    try:
        with open(telemetry.rapl_path, "r") as f:
            return int(f.read().strip())
    except:
        return telemetry.last_rapl_energy_uj

def monitor_loop():
    bpf_stats = bpf["stats"]
    prev_bpf = {i: {"duration_ns": 0, "calls": 0} for i in range(len(FUNCTIONS))}
    
    while True:
        time.sleep(0.1) # 100ms sampling window
        
        current_time_ns = time.time_ns()
        time_delta_ns = current_time_ns - telemetry.last_time_ns
        
        if time_delta_ns <= 0:
            continue
            
        current_rapl_uj = read_rapl_uj()
        rapl_delta_uj = current_rapl_uj - telemetry.last_rapl_energy_uj
        
        if rapl_delta_uj < 0:
            rapl_delta_uj = 0
            
        total_energy_mJ = rapl_delta_uj / 1000.0
        power_mW = total_energy_mJ / (time_delta_ns / 1e9)
        power_W = power_mW / 1000.0
        
        telemetry.last_time_ns = current_time_ns
        telemetry.last_rapl_energy_uj = current_rapl_uj
        
        with telemetry.lock:
            telemetry.total_power_w = power_W
            telemetry.total_energy_mj += total_energy_mJ
            
            total_tracked_ns = 0
            current_bpf_deltas = {}
            for i, func in enumerate(FUNCTIONS):
                try:
                    val = bpf_stats[bpf_stats.Key(i)]
                    dur = val.duration_ns
                    calls = val.calls
                except KeyError:
                    dur = 0
                    calls = 0
                    
                delta_ns = dur - prev_bpf[i]["duration_ns"]
                delta_calls = calls - prev_bpf[i]["calls"]
                
                prev_bpf[i]["duration_ns"] = dur
                prev_bpf[i]["calls"] = calls
                
                current_bpf_deltas[func] = {"duration_ns": delta_ns, "calls": delta_calls}
                total_tracked_ns += delta_ns
                
            for func, deltas in current_bpf_deltas.items():
                delta_ns = deltas["duration_ns"]
                calls = deltas["calls"]
                
                # Allocation math: energy = power_mW * duration_ns / 1e9
                func_energy_mJ = power_mW * (delta_ns / 1e9)
                
                if total_tracked_ns > 0:
                    cycle_share = (delta_ns / total_tracked_ns) * 100.0
                else:
                    cycle_share = 0.0
                
                telemetry.functions_data[func]["energy_mJ"] += func_energy_mJ
                telemetry.functions_data[func]["cycle_share"] = cycle_share
                telemetry.functions_data[func]["calls"] += calls
                telemetry.functions_data[func]["duration_ns"] += delta_ns

t = threading.Thread(target=monitor_loop, daemon=True)
t.start()

# ---------------------------------------------------------
# FASTAPI SERVER
# ---------------------------------------------------------
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/snapshot")
def get_snapshot():
    with telemetry.lock:
        return {
            "total_power_w": telemetry.total_power_w,
            "total_energy_mj": telemetry.total_energy_mj,
            "functions": telemetry.functions_data
        }

@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            with telemetry.lock:
                data = {
                    "total_power_w": telemetry.total_power_w,
                    "total_energy_mj": telemetry.total_energy_mj,
                    "functions": telemetry.functions_data
                }
            await websocket.send_json(data)
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        pass

import urllib.request
import json
from fastapi import Request

@app.post("/api/analyze")
async def analyze_telemetry(request: Request):
    data = await request.json()
    if not AI_API_KEY: return {"error": "API Key is missing in config.yaml"}
    
    req_body = json.dumps({
        "model": "openai/gpt-oss-20b",
        "messages": [{"role": "user", "content": data.get("prompt")}],
        "temperature": 0.7, 
        "max_tokens": 150
    }).encode('utf-8')
    
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=req_body,
        headers={
            "Authorization": f"Bearer {AI_API_KEY}",
            "HTTP-Referer": "http://localhost:8000",
            "X-Title": "EcoBPF Telemetry Dashboard",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0"
        },
        method="POST"
    )
    
    try:
        with urllib.request.urlopen(req) as response:
            res_data = json.loads(response.read().decode('utf-8'))
            if "choices" in res_data and len(res_data["choices"]) > 0:
                return {"result": res_data["choices"][0]["message"]["content"]}
            else:
                return {"error": f"OpenRouter JSON Error: {res_data}"}
    except urllib.error.HTTPError as e:
        try:
            error_info = e.read().decode('utf-8')
            return {"error": f"OpenRouter Error {e.code}: {error_info}"}
        except:
            return {"error": f"OpenRouter Error {e.code}"}
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    print(f"Starting server on {HOST}:{PORT}...")
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
