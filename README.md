# EcoBPF: eBPF-based Function-level Energy Profiler

A two-machine energy profiling setup using eBPF, RAPL, and WebSockets. 
Designed to run the profiler on a Linux machine and view the live telemetry on a separate machine via a web browser.

## Directory Structure
- `linux_agent/`: The collector code to run on the Linux machine with RAPL hardware.
- `mac_viewer/`: The self-contained HTML dashboard to open on your Mac.

## 1. Linux Setup (The Profiler)

1. **Install dependencies and open the firewall**:
   ```bash
   cd linux_agent
   chmod +x setup_linux.sh
   ./setup_linux.sh
   ```
   *(Note down the LAN IP address printed at the end of the script!)*

2. **Configure the Target Application**:
   Open `config.yaml` and set `target_binary` to the absolute path of your target application (e.g. `/usr/bin/redis-server`).
   List the exact function symbol names you want to trace under `functions:`.

3. **Run your Target Application** (if it's not already running).

4. **Start EcoBPF**:
   ```bash
   sudo python3 ecobpf.py -c config.yaml
   ```
   *(Must be run as root to attach uprobes and read the `/sys/class/powercap` RAPL registers)*.

## 2. Mac Setup (The Viewer)

1. Navigate to the `mac_viewer` directory on your Mac.
2. Double-click `dashboard.html` to open it in any modern browser (Chrome, Safari, Firefox).
3. In the top bar of the dashboard, enter the **Linux IP Address** (printed during `setup_linux.sh`) and click **Connect**.

> **Note on Remote Access**: The dashboard connects directly via the local network (LAN). If you want to access it remotely, you can use Tailscale (install on both machines and use the Tailscale IP) or establish an SSH tunnel: `ssh -L 8000:localhost:8000 user@linux-ip` and connect to `127.0.0.1:8000` on the dashboard.
