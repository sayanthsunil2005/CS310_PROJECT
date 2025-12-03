#Author : Sayanth Sunil

import tkinter as tk
from tkinter import ttk, font
import os
from collections import defaultdict

# --- Configuration ---
UPDATE_INTERVAL_MS = 2000  # How often to refresh the data (2 seconds)
CPU_HIGH_THRESHOLD = 75.0  # CPU % to highlight a process
MEM_HIGH_THRESHOLD_KB = 500 * 1024 # 500MB to highlight a process
USER_UID_MIN = 1000

class SystemExplorerApp:
 
    ##########   1. INITIAL VALUES AND SETUP   ##########
 
    def __init__(self, root):
        self.root = root
        self.root.title("Linux System Explorer By Sayanth Sunil")
        self.root.geometry("1200x700") # Widened window for new layout
        
        # --- Style and Fonts ---
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("Treeview", rowheight=25)
        self.style.configure("TProgressbar", thickness=20)
        self.header_font = font.Font(family="Helvetica", size=12, weight="bold")
        self.label_font = font.Font(family="Helvetica", size=10)

        # --- Data holders for CPU calculations ---
        self.cpu_core_count = os.cpu_count() or 1
        self.prev_sys_cpu_times = self.get_system_cpu_times()
        self.prev_proc_times = defaultdict(int)
        self.current_filter = "all" # 'all', 'user', or 'system'

        # Initialize the main UI components
        self.create_widgets()
        
        # Start the first update cycle
        self.update_all_info()

    ##########  2. GUI SETUP CODE  ##########  

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(expand=True, fill="both")
        
        # Create a top frame for the side-by-side CPU and Process monitors
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill="both", expand=True, pady=5)
        
        # Place CPU and Process monitors inside the top frame
        self.create_cpu_monitor_frame(top_frame)
        self.create_process_monitor_frame(top_frame)
        
        # Place the Memory monitor at the bottom of the main frame
        self.create_memory_monitor_frame(main_frame)
        
    def create_cpu_monitor_frame(self, parent):
        frame = ttk.LabelFrame(parent, text="CPU and Core Monitoring", padding="10")
        frame.pack(side="left", fill="both", expand=True, padx=(0, 5))
        
        ttk.Label(frame, text="Overall CPU Usage:", font=self.header_font).pack(anchor="w")
        self.overall_cpu_bar = ttk.Progressbar(frame, length=300, mode='determinate', style="TProgressbar")
        self.overall_cpu_bar.pack(fill="x", pady=5)
        self.overall_cpu_label = ttk.Label(frame, text="0.0%", font=self.label_font)
        self.overall_cpu_label.pack(anchor="w")

        ttk.Label(frame, text="Usage Per Core:", font=self.header_font).pack(anchor="w", pady=(10,0))
        self.core_bars = []
        self.core_labels = []
        for i in range(self.cpu_core_count):
            core_frame = ttk.Frame(frame)
            core_frame.pack(fill="x", pady=2)
            ttk.Label(core_frame, text=f"Core {i}:", width=7).pack(side="left")
            bar = ttk.Progressbar(core_frame, length=200, mode='determinate')
            bar.pack(side="left", fill="x", expand=True)
            label = ttk.Label(core_frame, text="0.0%", width=6)
            label.pack(side="left", padx=5)
            self.core_bars.append(bar)
            self.core_labels.append(label)

    def create_memory_monitor_frame(self, parent):
        frame = ttk.LabelFrame(parent, text="Memory Monitoring", padding="10")
        # Pack this frame to fill horizontally at the bottom
        frame.pack(fill="x", pady=(10, 0))
        
        # Use a sub-frame to organize the two memory bars
        mem_container = ttk.Frame(frame)
        mem_container.pack(fill="both", expand=True)
        
        self.mem_labels = {}
        for mem_type in ["RAM", "Swap"]:
            mem_frame = ttk.Frame(mem_container)
            mem_frame.pack(side="left", fill="x", expand=True, padx=10)
            
            ttk.Label(mem_frame, text=f"{mem_type} Usage:", font=self.header_font).pack(anchor="w", pady=(5,0))
            bar = ttk.Progressbar(mem_frame, length=300, mode='determinate', style="TProgressbar")
            bar.pack(fill="x", pady=5)
            label = ttk.Label(mem_frame, text="Calculating...", font=self.label_font)
            label.pack(anchor="w")
            self.mem_labels[mem_type] = {'bar': bar, 'label': label}

    def create_process_monitor_frame(self, parent):
        frame = ttk.LabelFrame(parent, text="Process Monitoring", padding="10")
        # Pack this frame to the side of the CPU monitor
        frame.pack(side="left", fill="both", expand=True, padx=(5, 0))

        # Filter buttons
        filter_frame = ttk.Frame(frame)
        filter_frame.pack(fill="x", pady=5)
        ttk.Button(filter_frame, text="All Processes", command=lambda: self.set_filter("all")).pack(side="left", padx=2)
        ttk.Button(filter_frame, text="User Processes", command=lambda: self.set_filter("user")).pack(side="left", padx=2)
        ttk.Button(filter_frame, text="System Processes", command=lambda: self.set_filter("system")).pack(side="left", padx=2)
        
        # Process list (Treeview)
        cols = ('pid', 'user', 'cpu', 'mem', 'status', 'command')
        self.tree = ttk.Treeview(frame, columns=cols, show='headings')
        
        for col in cols:
            self.tree.heading(col, text=col.capitalize())
        self.tree.column("pid", width=60, anchor="center")
        self.tree.column("user", width=80)
        self.tree.column("cpu", width=60, anchor="e")
        self.tree.column("mem", width=80, anchor="e")
        self.tree.column("status", width=100)
        self.tree.column("command", width=300)
        
        # Tags for color coding
        self.tree.tag_configure('high_cpu', background='orangered')
        self.tree.tag_configure('high_mem', background='deepskyblue')
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
            
    
    ########  3. CPU AND CORE MONITORING - LOGIC  ##########
    
    def get_system_cpu_times(self):
        """Reads /proc/stat to get total and per-core CPU times."""
        try:
            with open('/proc/stat', 'r') as f:
                lines = f.readlines()
            
            # Overall is the first line, 'cpu'
            overall_times = [int(p) for p in lines[0].split()[1:]]
            
            # Per-core lines start with 'cpuX'
            core_times = []
            for i in range(self.cpu_core_count):
                core_line = lines[i + 1]
                core_times.append([int(p) for p in core_line.split()[1:]])
            return {'overall': overall_times, 'cores': core_times}
        except (IOError, ValueError):
            return {'overall': [0]*10, 'cores': [[0]*10 for _ in range(self.cpu_core_count)]}

    def update_cpu_info(self):
        current_sys_cpu_times = self.get_system_cpu_times()
        
        # --- Overall CPU Calculation Logic ---
        prev_overall = self.prev_sys_cpu_times['overall']
        curr_overall = current_sys_cpu_times['overall']
        
        prev_total = sum(prev_overall)
        curr_total = sum(curr_overall)
        prev_idle = prev_overall[3]
        curr_idle = curr_overall[3]

        total_delta = curr_total - prev_total
        idle_delta = curr_idle - prev_idle
        
        cpu_usage = 0.0
        if total_delta > 0:
            cpu_usage = 100.0 * (1.0 - idle_delta / total_delta)
        
        self.overall_cpu_bar['value'] = cpu_usage
        self.overall_cpu_label['text'] = f"{cpu_usage:.1f}%"
        
        # --- Per-Core CPU Calculation Logic ---
        for i in range(self.cpu_core_count):
            prev_core = self.prev_sys_cpu_times['cores'][i]
            curr_core = current_sys_cpu_times['cores'][i]
            
            prev_total_core = sum(prev_core)
            curr_total_core = sum(curr_core)
            prev_idle_core = prev_core[3]
            curr_idle_core = curr_core[3]

            total_delta_core = curr_total_core - prev_total_core
            idle_delta_core = curr_idle_core - prev_idle_core
            
            core_usage = 0.0
            if total_delta_core > 0:
                core_usage = 100.0 * (1.0 - idle_delta_core / total_delta_core)
                
            self.core_bars[i]['value'] = core_usage
            self.core_labels[i]['text'] = f"{core_usage:.1f}%"

        self.prev_sys_cpu_times = current_sys_cpu_times

    ##########  MEMORY MONITORING - LOGIC  ##########

    def update_memory_info(self):
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
            
            meminfo = {line.split(':')[0]: int(line.split(':')[1].strip().split()[0]) for line in lines}
            
            # RAM Calculation
            mem_total = meminfo.get('MemTotal', 1)
            mem_available = meminfo.get('MemAvailable', 1)
            mem_used = mem_total - mem_available
            mem_percent = (mem_used / mem_total) * 100
            
            self.mem_labels["RAM"]['bar']['value'] = mem_percent
            self.mem_labels["RAM"]['label']['text'] = f"Used: {mem_used/1024:.1f} MB / {mem_total/1024:.1f} MB ({mem_percent:.1f}%)"
            
            # Swap Calculation
            swap_total = meminfo.get('SwapTotal', 1)
            swap_free = meminfo.get('SwapFree', 1)
            swap_used = swap_total - swap_free
            swap_percent = 0
            if swap_total > 0:
                swap_percent = (swap_used / swap_total) * 100
            
            self.mem_labels["Swap"]['bar']['value'] = swap_percent
            self.mem_labels["Swap"]['label']['text'] = f"Used: {swap_used/1024:.1f} MB / {swap_total/1024:.1f} MB ({swap_percent:.1f}%)"

        except (IOError, ValueError):
            pass


    ##########   PROCESS MONITORING - LOGIC  ##########

    def set_filter(self, filter_type):
        self.current_filter = filter_type

    def get_process_data(self):
        processes = []
        pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
        
        current_proc_times = defaultdict(int)
        
        # Get total system CPU time delta
        prev_total_sys_time = sum(self.prev_sys_cpu_times['overall'])
        curr_total_sys_time = sum(self.get_system_cpu_times()['overall'])
        sys_time_delta = curr_total_sys_time - prev_total_sys_time
        if sys_time_delta == 0: sys_time_delta = 1

        for pid in pids:
            try:
                # CPU time from /proc/[pid]/stat
                with open(f'/proc/{pid}/stat', 'r') as f:
                    stat_data = f.read().split()
                proc_total_time = int(stat_data[13]) + int(stat_data[14])
                current_proc_times[pid] = proc_total_time
                
                proc_time_delta = proc_total_time - self.prev_proc_times.get(pid, 0)
                cpu_percent = 100.0 * (proc_time_delta / sys_time_delta)
                
                # Other info from /proc/[pid]/status
                proc_info = {}
                with open(f'/proc/{pid}/status', 'r') as f:
                    for line in f:
                        key, value = line.split(':', 1)
                        if key.strip() in ['Name', 'State', 'Uid', 'VmRSS']:
                            proc_info[key.strip()] = value.strip()
                
                # Command from /proc/[pid]/cmdline
                cmdline = proc_info.get('Name', 'N/A')
                with open(f'/proc/{pid}/cmdline', 'r') as f:
                    full_cmd = f.read().replace('\0', ' ').strip()
                    if full_cmd: cmdline = full_cmd

                mem_kb = int(proc_info.get('VmRSS', '0 kB').replace('kB', '').strip())
                uid = int(proc_info.get('Uid', '0').split()[0])

                proc_data = {
                    'pid': pid, 'user': 'root' if uid == 0 else str(uid), 'cpu': f"{cpu_percent:.1f}", 
                    'mem': f"{mem_kb/1024:.1f}M", 'status': proc_info.get('State', '?'), 
                    'command': cmdline, 'uid': uid, 'mem_raw': mem_kb, 'cpu_raw': cpu_percent
                }
                processes.append(proc_data)
            except (IOError, IndexError, ValueError):
                continue
        
        self.prev_proc_times = current_proc_times
        return processes

    def update_process_info(self):
        # Clear existing entries
        for i in self.tree.get_children():
            self.tree.delete(i)
        
        processes = self.get_process_data()

        # Apply filter
        if self.current_filter == 'user':
            processes = [p for p in processes if p['uid'] >= USER_UID_MIN]
        elif self.current_filter == 'system':
            processes = [p for p in processes if p['uid'] < USER_UID_MIN]

        # Sort by CPU
        processes.sort(key=lambda p: p['cpu_raw'], reverse=True)
        
        # Populate the treeview
        for proc in processes:
            tags = []
            if proc['cpu_raw'] > CPU_HIGH_THRESHOLD:
                tags.append('high_cpu')
            if proc['mem_raw'] > MEM_HIGH_THRESHOLD_KB:
                tags.append('high_mem')
                
            self.tree.insert('', 'end', values=(
                proc['pid'], proc['user'], proc['cpu'], proc['mem'], proc['status'], proc['command']
            ), tags=tuple(tags))

    
    ##########    MAIN UPDATE LOOP  ##########
    def update_all_info(self):
        """This is the main loop that refreshes all UI components."""
        self.update_cpu_info()
        self.update_memory_info()
        self.update_process_info()
        
        # Schedule the next update
        self.root.after(UPDATE_INTERVAL_MS, self.update_all_info)

if __name__ == '__main__':
    # Ensure tkinter is available
    try:
        root = tk.Tk()
        app = SystemExplorerApp(root)
        root.mainloop()
    except tk.TclError:
        print("tkinter is not installed or could not be initialized.")
        print("Please install it. On Debian/Ubuntu: sudo apt-get install python3-tk")
