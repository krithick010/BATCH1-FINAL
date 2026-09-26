#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

void do_heavy_work() {
    long long sum = 0;
    for (int i = 0; i < 40000000; i++) sum += i;
}

void do_medium_work() {
    long long sum = 0;
    for (int i = 0; i < 15000000; i++) sum += i;
}

void do_light_work() {
    long long sum = 0;
    for (int i = 0; i < 2000000; i++) sum += i;
}

// Spikes up randomly to make the chart look cool
void do_burst_work() {
    long long sum = 0;
    int limit = (rand() % 10 > 7) ? 80000000 : 100000; 
    for (int i = 0; i < limit; i++) sum += i;
}

// Sleeps a lot, uses barely any CPU (shows BPF cycle vs time difference!)
void do_sleepy_work() {
    usleep(20000); // Sleep 20ms
}

int main() {
    srand(time(NULL));
    printf("Running SUPER COOL dummy app...\n");
    printf("Watch the dashboard for the random 'burst' spikes!\n");
    
    while (1) {
        do_heavy_work();
        do_medium_work();
        do_light_work();
        do_burst_work();
        do_sleepy_work();
        usleep(10000);
    }
    return 0;
}
