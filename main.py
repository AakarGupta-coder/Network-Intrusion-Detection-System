import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, Toplevel
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import deque
from datetime import datetime
import psutil
import threading
import time

# --- Scapy for Network Sniffing ---
from scapy.all import sniff, IP, TCP, Raw

# --- Parser Classes (No change from last robust version) ---
class SQLInjectionParser:
    def __init__(self, payload):
        self.payload = payload.strip()

    def parse(self):
        payload_lower = self.payload.lower()
        patterns = [
            "' or '1'='1' --",
            "' or 1=1 --",
            "' or '1'='1",
            "' or 1=1"
        ]
        for pattern in patterns:
            if payload_lower.find(pattern) != -1:
                return True
        return False

class XSSParser:
    def __init__(self, payload):
        self.payload = payload.strip()

    def _find_tag_pair(self, open_tag, close_tag):
        payload_lower = self.payload.lower()
        open_tag_lower = open_tag.lower()
        close_tag_lower = close_tag.lower()
        
        current_search_pos = 0
        while True:
            start_index = payload_lower.find(open_tag_lower, current_search_pos)
            if start_index == -1:
                return False
            content_start_pos = start_index + len(open_tag)
            end_index = payload_lower.find(close_tag_lower, content_start_pos)
            if end_index == -1:
                current_search_pos = content_start_pos
            else:
                return True
        
    def parse(self):
        if self._find_tag_pair("<script>", "</script>"):
            return True
        return False

# --- NIDS Engine (No change from last robust version) ---
class NIDSEngine:
    def __init__(self):
        self.parsers = {
            "SQL Injection": SQLInjectionParser,
            "XSS (Script Tag)": XSSParser
        }
        self.more_info_data = {
            "SQL Injection": {
                "grammar": "Grammar: [prefix]' OR '1'='1'--[suffix] OR [prefix]' OR 1=1 --[suffix] (and variants)",
                "description": "This attack injects malicious SQL code into query inputs. The grammar is designed to recognize common bypass techniques where an attacker uses a tautology (`'1'='1'`) to gain unauthorized access, often followed by comments.",
                "effects": "• Data Theft: Access to sensitive database information.\n• Data Corruption: Unauthorized modification or deletion of data.\n• Server Takeover: Potential for remote code execution on the database server.",
                "mitigation_toc": "By defining a strict Context-Free Grammar for valid inputs and rejecting any input that conforms to this malicious grammar, we can precisely block these attacks. The parser acts as a deterministic recognizer for a language of malicious strings.",
                "simulation": {
                    "scenario": "Simulating unauthorized database access...",
                    "steps": [
                        "1. Attacker sends payload: {payload_placeholder}",
                        "2. Web application attempts to execute query.",
                        "3. Malicious logic bypasses authentication.",
                        "4. Database returns ALL user records."
                    ],
                    "output_sample": [
                        "--- Simulated Database Query Result ---",
                        "User ID | Username   | Password_Hash",
                        "------------------------------------",
                        "1       | admin      | $2a$10$abc...",
                        "2       | user1      | $2a$10$def...",
                        "3       | guest      | $2a$10$ghi...",
                        "... and so on ...",
                        "------------------------------------",
                        "EFFECT: Full data exposure without authentication."
                    ]
                }
            },
            "XSS (Script Tag)": {
                "grammar": "Grammar: <script>[any content]</script>",
                "description": "Cross-Site Scripting injects malicious scripts into trusted websites, which then execute on a victim's browser. This specific grammar targets the use of basic script tags.",
                "effects": "• Session Hijacking: Stealing user session cookies to impersonate them.\n• Defacement: Modifying website content.\n• Phishing: Redirecting users to malicious sites to steal credentials.",
                "mitigation_toc": "The grammar identifies the fundamental structure of a script injection. The parser recognizes the language defined by `L = {<script>w</script> | w is any string}`. By rejecting any payload in this language, we prevent the script from being processed by the application.",
                "simulation": {
                    "scenario": "Simulating a browser-side XSS attack...",
                    "steps": [
                        "1. Attacker injects payload: {payload_placeholder}",
                        "2. Victim visits compromised page.",
                        "3. Browser executes injected script.",
                        "4. Malicious action is performed (e.g., alert, cookie theft, redirect)."
                    ],
                    "output_sample": [
                        "--- Simulated Browser Activity ---",
                        "[Browser Console] Received data containing {payload_placeholder}",
                        "[Browser Display] A popup window appears with message: 'You are hacked!'",
                        "[Network Traffic] Potential request to attacker's server with stolen cookies (e.g., GET /steal?cookie=...) ",
                        "EFFECT: Client-side compromise, data theft, or user manipulation."
                    ]
                }
            }
        }

    def analyze_payload(self, payload):
        detections = []
        for threat_type, ParserClass in self.parsers.items():
            parser = ParserClass(payload)
            if parser.parse():
                detections.append(threat_type)
        return detections

# --- New Traffic Sniffer Class ---
class TrafficSniffer:
    def __init__(self, callback_fn):
        self.callback_fn = callback_fn
        self._stop_event = threading.Event()
        self.sniff_thread = None

    def _packet_handler(self, packet):
        payload_data = ""
        src_ip = "N/A"
        dst_ip = "N/A"
        sport = "N/A"
        dport = "N/A"

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport

            # Check for HTTP (ports 80, 8080) or HTTPS (port 443 - though encrypted, we can still get some metadata)
            # This is a simplified approach. Real NIDS uses deep packet inspection.
            if packet.haslayer(Raw):
                try:
                    # Attempt to decode as HTTP data. If it's encrypted HTTPS, this might be garbled.
                    # For a real NIDS, this is where you'd integrate TLS decryption if you controlled the keys.
                    payload_data = packet[Raw].load.decode('utf-8', errors='ignore')
                except Exception:
                    payload_data = str(packet[Raw].load) # Fallback

        # Only pass on packets with substantial payload data for analysis
        if payload_data:
            self.callback_fn(f"[{src_ip}:{sport} -> {dst_ip}:{dport}] {payload_data}")

        # Check if stop event is set to terminate sniffing
        if self._stop_event.is_set():
            return True # This tells sniff to stop

    def start_sniffing(self, iface=None, filter="ip and tcp and (port 80 or port 8080 or port 443)", count=0):
        # iface: e.g., "eth0", "Wi-Fi", "en0". If None, Scapy tries to guess.
        # filter: BPF filter. Focus on common HTTP/HTTPS ports.
        # count=0 means sniff indefinitely.
        print(f"Starting sniffing on {iface if iface else 'all interfaces'} with filter '{filter}'...")
        self._stop_event.clear()
        self.sniff_thread = threading.Thread(target=sniff, kwargs={
            "prn": self._packet_handler, 
            "store": 0, 
            "stop_filter": lambda p: self._stop_event.is_set(),
            "iface": iface,
            "filter": filter,
            "count": count
        })
        self.sniff_thread.daemon = True # Allow main program to exit even if thread is running
        self.sniff_thread.start()

    def stop_sniffing(self):
        if self.sniff_thread and self.sniff_thread.is_alive():
            print("Signaling sniff thread to stop...")
            self._stop_event.set()
            # Give it a moment to actually stop, can be aggressive with a join timeout
            self.sniff_thread.join(timeout=2) 
            if self.sniff_thread.is_alive():
                print("Warning: Sniff thread might still be active. Force stopping might be needed on some systems.")
            self.sniff_thread = None


# --- NIDS Application (Modified for Live Sniffing) ---
class NIDSApp:
    def __init__(self, master):
        self.master = master
        master.title("Live NIDS Dashboard - Aakar Gupta")
        master.geometry("1400x850")

        self.current_theme = "dark"
        self._setup_styles()
        
        self.nids_engine = NIDSEngine()
        self.intrusion_log = deque(maxlen=100)
        self.detection_counts = {"SQL Injection": 0, "XSS (Script Tag)": 0, "Benign": 0}
        self.selected_intrusion_type = None 
        self.selected_payload = None

        self.sniffer = TrafficSniffer(self._handle_sniffed_data)
        self.sniffing_active = False

        self._create_widgets()
        self._setup_graphs()
        self.toggle_theme(initial_setup=True)

        self.last_net_io = psutil.net_io_counters()
        self.net_io_data = deque(maxlen=60)
        self.network_monitoring_active = False # Start inactive
        self._update_network_monitor_if_active() # Kick off initial check

    def _setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')

    def _configure_theme_styles(self):
        is_dark = self.current_theme == "dark"
        
        bg_color = "#2E2E2E" if is_dark else "#F0F0F0"
        panel_bg = "#3C3C3C" if is_dark else "#FFFFFF"
        text_color = "#E0E0E0" if is_dark else "#333333"
        log_bg = "#3C3C3C" if is_dark else "#F5F5F5"
        log_fg_benign = "#77DD77" if is_dark else "#228B22"
        log_fg_malicious = "#FF6B6B" if is_dark else "#C70039"
        entry_field_bg = "#5E5E5E" if is_dark else "#FFFFFF"
        button_bg = "#5E5E5E" if is_dark else "#DDDDDD"
        button_fg = "#FFFFFF" if is_dark else "#333333"
        tree_field_bg = "#5E5E5E" if is_dark else "#FFFFFF"
        tree_fg = "#E0E0E0" if is_dark else "#333333"
        header_fg = "#FFFFFF" if is_dark else "#111111"
        footer_fg = "#9E9E9E" if is_dark else "#666666"
        tree_selected_bg = "#007ACC" if is_dark else "#ADD8E6"

        self.master.configure(bg=bg_color)
        self.style.configure('TFrame', background=bg_color)
        self.style.configure('Dark.TLabelframe', background=panel_bg, foreground=text_color, font=('Segoe UI', 12, 'bold'))
        self.style.configure('Dark.TLabelframe.Label', background=panel_bg, foreground=text_color, font=('Segoe UI', 12, 'bold'))
        self.style.configure('TLabel', background=panel_bg, foreground=text_color, font=('Segoe UI', 10))
        self.style.configure('Header.TLabel', background=bg_color, foreground=header_fg, font=('Segoe UI', 20, 'bold'))
        self.style.configure('Footer.TLabel', background=bg_color, foreground=footer_fg, font=('Segoe UI', 8))
        self.style.configure('TButton', background=button_bg, foreground=button_fg, font=('Segoe UI', 10, 'bold'), borderwidth=0)
        self.style.map('TButton', background=[('active', '#7E7E7E' if is_dark else '#BBBBBB')])
        self.style.configure('TEntry', fieldbackground=entry_field_bg, foreground=text_color, borderwidth=0)
        self.style.configure('Treeview', background=tree_field_bg, foreground=tree_fg, fieldbackground=tree_field_bg, borderwidth=0)
        self.style.map('Treeview', background=[('selected', tree_selected_bg)])
        self.style.configure('Treeview.Heading', background=panel_bg, foreground=text_color, font=('Segoe UI', 10, 'bold'))
        
        self.log_text.configure(background=log_bg, insertbackground=text_color)
        self.log_text.tag_config("green", foreground=log_fg_benign)
        self.log_text.tag_config("red", foreground=log_fg_malicious)
        
        if hasattr(self, 'bar_fig'):
            self._update_graphs()

    def toggle_theme(self, initial_setup=False):
        if not initial_setup:
            if self.current_theme == "dark":
                self.current_theme = "light"
                self.theme_button.config(text="Dark Mode")
            else:
                self.current_theme = "dark"
                self.theme_button.config(text="Light Mode")
        self._configure_theme_styles()

    def _create_widgets(self):
        header_frame = ttk.Frame(self.master, style='TFrame')
        header_frame.pack(fill=tk.X, pady=(10, 5), padx=20)
        ttk.Label(header_frame, text="Live Grammar-Based NIDS", style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 20))
        
        self.theme_button = ttk.Button(header_frame, text="Light Mode", command=self.toggle_theme)
        self.theme_button.pack(side=tk.RIGHT, padx=5)
        ttk.Button(header_frame, text="About This App", command=self._show_about_info).pack(side=tk.RIGHT, padx=5)
        
        self.more_info_button = ttk.Button(header_frame, text="More Info", command=self._show_more_info)
        self.more_info_button.pack(side=tk.RIGHT, padx=5)
        self.more_info_button.pack_forget()
        
        ttk.Button(header_frame, text="Network Info", command=self._show_network_info).pack(side=tk.RIGHT, padx=5)

        self.main_frame = ttk.Frame(self.master, padding="10 10 10 20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.left_panel = ttk.Frame(self.main_frame, width=500, style='TFrame')
        self.left_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=10, pady=5)

        self.right_panel = ttk.Frame(self.main_frame, style='TFrame')
        self.right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=5)

        # --- Live Sniffing Controls ---
        self.sniff_control_frame = ttk.LabelFrame(self.left_panel, text="Live Traffic Analysis", style="Dark.TLabelframe", padding="10")
        self.sniff_control_frame.pack(fill=tk.X, pady=10)

        ttk.Label(self.sniff_control_frame, text="Interface (optional, e.g., eth0, Wi-Fi):", style='TLabel').pack(anchor=tk.W, pady=(0, 5))
        self.iface_entry = ttk.Entry(self.sniff_control_frame, width=40, font=('Segoe UI', 10))
        self.iface_entry.pack(fill=tk.X, pady=(0, 5))
        
        self.start_sniff_button = ttk.Button(self.sniff_control_frame, text="Start Sniffing", command=self._start_sniffing)
        self.start_sniff_button.pack(side=tk.LEFT, expand=True, padx=(0, 5))
        self.stop_sniff_button = ttk.Button(self.sniff_control_frame, text="Stop Sniffing", command=self._stop_sniffing, state=tk.DISABLED)
        self.stop_sniff_button.pack(side=tk.RIGHT, expand=True, padx=(5, 0))
        
        # --- Manual Payload Analysis (still useful for testing) ---
        self.manual_frame = ttk.LabelFrame(self.left_panel, text="Manual Payload Analysis", style="Dark.TLabelframe", padding="10")
        self.manual_frame.pack(fill=tk.X, pady=10)

        ttk.Label(self.manual_frame, text="Enter Payload:", style='TLabel').pack(anchor=tk.W, pady=(0, 5))
        self.payload_entry = ttk.Entry(self.manual_frame, width=50, font=('Segoe UI', 10))
        self.payload_entry.pack(fill=tk.X, pady=(0, 10))
        self.payload_entry.bind('<Return>', lambda event: self._manual_detect())

        ttk.Button(self.manual_frame, text="Analyze Payload", command=self._manual_detect).pack(fill=tk.X)

        self.log_frame = ttk.LabelFrame(self.left_panel, text="Activity Log", style="Dark.TLabelframe", padding="10")
        self.log_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.log_text = scrolledtext.ScrolledText(self.log_frame, wrap=tk.WORD, height=15, font=('Consolas', 9), relief="flat")
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)

        self.history_frame = ttk.LabelFrame(self.left_panel, text="Detection History", style="Dark.TLabelframe", padding="10")
        self.history_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.tree = ttk.Treeview(self.history_frame, columns=("Time", "Source", "Destination", "Payload Sample", "Type"), show="headings", height=8)
        self.tree.heading("Time", text="Time", anchor=tk.W)
        self.tree.heading("Source", text="Src IP:Port", anchor=tk.W)
        self.tree.heading("Destination", text="Dst IP:Port", anchor=tk.W)
        self.tree.heading("Payload Sample", text="Payload Sample", anchor=tk.W)
        self.tree.heading("Type", text="Type", anchor=tk.W)
        self.tree.column("Time", width=120, stretch=tk.NO)
        self.tree.column("Source", width=100, stretch=tk.NO)
        self.tree.column("Destination", width=100, stretch=tk.NO)
        self.tree.column("Payload Sample", width=150, stretch=tk.YES)
        self.tree.column("Type", width=100, stretch=tk.NO)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind('<<TreeviewSelect>>', self._on_tree_select)

        self.summary_frame = ttk.LabelFrame(self.right_panel, text="Dashboard Summary", style="Dark.TLabelframe", padding="10")
        self.summary_frame.pack(fill=tk.X, pady=5)
        
        self.total_intrusions_label = ttk.Label(self.summary_frame, text="Total Intrusions: 0", font=('Segoe UI', 11, 'bold'), style='TLabel')
        self.total_intrusions_label.pack(anchor=tk.W, pady=2)
        self.total_processed_label = ttk.Label(self.summary_frame, text="Total Processed: 0", font=('Segoe UI', 11, 'bold'), style='TLabel')
        self.total_processed_label.pack(anchor=tk.W, pady=2)

        self.graphs_container = ttk.Frame(self.right_panel, style='TFrame')
        self.graphs_container.pack(fill=tk.BOTH, expand=True, pady=5)
        self.graphs_container.grid_columnconfigure(0, weight=1)
        self.graphs_container.grid_columnconfigure(1, weight=1)
        self.graphs_container.grid_rowconfigure(0, weight=1)

        self.bar_graph_frame = ttk.LabelFrame(self.graphs_container, text="Threat Breakdown", style="Dark.TLabelframe", padding="10")
        self.bar_graph_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        
        self.pie_chart_frame = ttk.LabelFrame(self.graphs_container, text="Traffic Analysis", style="Dark.TLabelframe", padding="10")
        self.pie_chart_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))

        ttk.Label(self.master, text="Aakar Gupta - 24BRS1321", style="Footer.TLabel").pack(side=tk.BOTTOM, pady=(10, 5))

        # Handle window closing to stop sniffing gracefully
        self.master.protocol("WM_DELETE_WINDOW", self._on_closing)


    def _on_closing(self):
        if self.sniffing_active:
            self._stop_sniffing()
        if self.network_monitoring_active:
            self._stop_network_monitoring()
        self.master.destroy()

    def _start_sniffing(self):
        if not self.sniffing_active:
            iface = self.iface_entry.get().strip()
            # Iface must be specified or Scapy will pick one. On some systems, picking explicitly is better.
            # Example: iface="Wi-Fi" for Windows, "en0" for macOS, "eth0" for Linux
            
            try:
                self.sniffer.start_sniffing(iface=iface if iface else None)
                self.sniffing_active = True
                self.start_sniff_button.config(state=tk.DISABLED)
                self.stop_sniff_button.config(state=tk.NORMAL)
                self._log_message("Live sniffing started...", "green")
            except Exception as e:
                messagebox.showerror("Sniffing Error", f"Failed to start sniffing: {e}\n\n"
                                     "Ensure you have `scapy` installed and are running the application with "
                                     "administrator/root privileges. On Windows, ensure Npcap is installed.")
                self._log_message(f"Error starting sniffing: {e}", "red")

    def _stop_sniffing(self):
        if self.sniffing_active:
            self.sniffer.stop_sniffing()
            self.sniffing_active = False
            self.start_sniff_button.config(state=tk.NORMAL)
            self.stop_sniff_button.config(state=tk.DISABLED)
            self._log_message("Live sniffing stopped.", "green")

    def _handle_sniffed_data(self, full_packet_info):
        # This function runs in the sniffing thread, so we need to use after()
        # to safely update the Tkinter GUI from the main thread.
        self.master.after(0, self._process_sniffed_payload, full_packet_info)

    def _process_sniffed_payload(self, full_packet_info):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # full_packet_info looks like "[src_ip:sport -> dst_ip:dport] PAYLOAD_DATA"
        # Extract payload and connection info
        parts = full_packet_info.split("] ", 1)
        connection_info = parts[0][1:] # Remove leading '['
        payload_data = parts[1] if len(parts) > 1 else ""

        src_dest_parts = connection_info.split(" -> ")
        source = src_dest_parts[0] if len(src_dest_parts) > 0 else "N/A"
        destination = src_dest_parts[1] if len(src_dest_parts) > 1 else "N/A"

        detected_types = self.nids_engine.analyze_payload(payload_data)

        payload_sample = payload_data.replace('\n', '\\n').replace('\r', '\\r')
        if len(payload_sample) > 50:
            payload_sample = payload_sample[:47] + "..." # Truncate for display

        if detected_types:
            self._log_message(f"[{now}] 🚨 INTRUSION DETECTED: {connection_info} -> '{payload_sample}'", "red")
            self.intrusion_log.append({
                "time": now, 
                "source": source,
                "destination": destination,
                "payload": payload_data, # Store full payload for more info
                "payload_sample": payload_sample, # Store truncated for history table
                "types": detected_types
            })
            for d_type in detected_types:
                self.detection_counts[d_type] += 1
        else:
            self._log_message(f"[{now}] ✅ Benign Traffic: {connection_info} -> '{payload_sample}'", "green")
            self.detection_counts["Benign"] += 1
        
        self._update_dashboard()

    def _on_tree_select(self, event):
        selected_items = self.tree.selection()
        if not selected_items:
            self.more_info_button.pack_forget()
            self.selected_intrusion_type = None
            self.selected_payload = None
            return

        selected_item = selected_items[0]
        # Retrieve the full log entry, not just the displayed values
        index = self.tree.get_children().index(selected_item) # Get position in tree
        # Intrusion log is reversed, so we need to adjust index
        actual_log_index = len(self.intrusion_log) - 1 - index 
        log_entry = self.intrusion_log[actual_log_index]

        detected_types_str = ', '.join(log_entry['types'])
        payload = log_entry['payload']
        
        detected_types = [t.strip() for t in detected_types_str.split(',')]
        
        self.selected_intrusion_type = None
        for d_type in detected_types:
            if d_type in self.nids_engine.more_info_data:
                self.selected_intrusion_type = d_type
                self.selected_payload = payload
                break
        
        if self.selected_intrusion_type:
            self.more_info_button.pack(side=tk.RIGHT, padx=5)
        else:
            self.more_info_button.pack_forget()

    def _log_message(self, message, color_tag="default"):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n", color_tag)
        self.log_text.yview(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def _update_dashboard(self):
        total_intrusions = sum(self.detection_counts[k] for k in self.detection_counts if k != "Benign")
        total_processed = sum(self.detection_counts.values())
        self.total_intrusions_label.config(text=f"Total Intrusions: {total_intrusions}")
        self.total_processed_label.config(text=f"Total Processed: {total_processed}")

        for item in self.tree.get_children():
            self.tree.delete(item)
        for entry in reversed(self.intrusion_log):
            self.tree.insert("", tk.END, values=(
                entry['time'], 
                entry['source'], 
                entry['destination'], 
                entry['payload_sample'], 
                ', '.join(entry['types'])
            ))
        
        self._update_graphs()

    def _manual_detect(self):
        payload = self.payload_entry.get()
        if not payload:
            messagebox.showwarning("Empty Payload", "Please enter a payload to analyze.")
            return
        self.payload_entry.delete(0, tk.END)
        
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        detected_types = self.nids_engine.analyze_payload(payload)

        payload_sample = payload.replace('\n', '\\n').replace('\r', '\\r')
        if len(payload_sample) > 50:
            payload_sample = payload_sample[:47] + "..."

        if detected_types:
            self._log_message(f"[{now}] 🚨 INTRUSION DETECTED (Manual): '{payload}'", "red")
            self.intrusion_log.append({
                "time": now, 
                "source": "Manual Input",
                "destination": "N/A",
                "payload": payload,
                "payload_sample": payload_sample,
                "types": detected_types
            })
            for d_type in detected_types:
                self.detection_counts[d_type] += 1
        else:
            self._log_message(f"[{now}] ✅ Benign Payload (Manual): '{payload}'", "green")
            self.detection_counts["Benign"] += 1
        
        self._update_dashboard()

    def _setup_graphs(self):
        self.bar_fig, self.bar_ax = plt.subplots(figsize=(6, 4))
        self.pie_fig, self.pie_ax = plt.subplots(figsize=(6, 4))
        self.bar_canvas = FigureCanvasTkAgg(self.bar_fig, master=self.bar_graph_frame)
        self.bar_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        self.pie_canvas = FigureCanvasTkAgg(self.pie_fig, master=self.pie_chart_frame)
        self.pie_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def _update_graphs(self):
        is_dark = self.current_theme == "dark"
        mpl_bg = "#3C3C3C" if is_dark else "#FFFFFF"
        mpl_text = "#E0E0E0" if is_dark else "#333333"
        pie_colors = ['#2E8B57', '#B22222'] if is_dark else ['#3CB371', '#DC143C']
        bar_colors = ['#FF6347', '#4682B4'] if is_dark else ['#FF4500', '#1E90FF']

        self.bar_ax.clear()
        self.bar_fig.set_facecolor(mpl_bg)
        self.bar_ax.set_facecolor(mpl_bg)
        bar_labels = [k for k in self.detection_counts if k != "Benign"]
        bar_values = [self.detection_counts[k] for k in bar_labels]
        bars = self.bar_ax.bar(bar_labels, bar_values, color=bar_colors)
        self.bar_ax.set_title("Threat Detections", color=mpl_text)
        self.bar_ax.set_ylabel("Count", color=mpl_text)
        self.bar_ax.tick_params(axis='x', colors=mpl_text, labelsize=8)
        self.bar_ax.tick_params(axis='y', colors=mpl_text, labelsize=8)
        self.bar_ax.set_ylim(bottom=0, top=max(1, max(bar_values, default=0) * 1.1))
        for spine in self.bar_ax.spines.values():
            spine.set_edgecolor(mpl_text)
        for bar in bars:
            yval = bar.get_height()
            text_y_position = 0.1 if yval == 0 else yval / 2
            self.bar_ax.text(bar.get_x() + bar.get_width()/2.0, text_y_position, int(yval), ha='center', va='center', color=mpl_text, fontweight='bold')
        self.bar_fig.tight_layout()
        self.bar_canvas.draw_idle()
        
        self.pie_ax.clear()
        self.pie_fig.set_facecolor(mpl_bg)
        total_intrusions = sum(self.detection_counts[k] for k in self.detection_counts if k != "Benign")
        pie_labels = ['Benign', 'Malicious']
        pie_values = [self.detection_counts['Benign'], total_intrusions]
        explode = (0, 0.1) if total_intrusions > 0 else (0, 0)
        
        if sum(pie_values) > 0:
            self.pie_ax.pie(pie_values, labels=pie_labels, autopct='%1.1f%%', startangle=140, colors=pie_colors, explode=explode, textprops={'color': mpl_text, 'fontweight': 'bold'})
        else:
            self.pie_ax.pie([1], labels=['No Data'], colors=['#555555'], textprops={'color': mpl_text})
        self.pie_ax.set_title("Benign vs. Malicious Traffic", color=mpl_text)
        self.pie_fig.tight_layout()
        self.pie_canvas.draw_idle()

    def _create_themed_toplevel(self, title, geometry):
        window = Toplevel(self.master)
        window.title(title)
        window.geometry(geometry)
        window.grab_set()
        window.transient(self.master)
        bg = "#2E2E2E" if self.current_theme == "dark" else "#F0F0F0"
        window.configure(bg=bg)
        return window

    def _show_about_info(self):
        about_window = self._create_themed_toplevel("About This App", "550x350")
        
        text_bg = "#3C3C3C" if self.current_theme == "dark" else "#FFFFFF"
        text_fg = "#E0E0E0" if self.current_theme == "dark" else "#333333"

        info_frame = ttk.Frame(about_window, padding=20, style='TFrame')
        info_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(info_frame, text="About This NIDS Application", font=('Segoe UI', 14, 'bold'), style='Header.TLabel').pack(pady=(5, 15))

        details_text = tk.Text(info_frame, wrap=tk.WORD, font=('Segoe UI', 10),
                               bg=text_bg, fg=text_fg, relief="flat", borderwidth=0)
        about_info = """
This Network Intrusion Detection System (NIDS) provides real-time monitoring and analysis of network traffic to detect common cyber threats like SQL Injection and Cross-Site Scripting (XSS).

It employs a rule-based, signature detection methodology to identify malicious patterns within network payloads. The system offers a dynamic dashboard for visual insights, a detailed activity log, and attack simulations to demonstrate potential impacts.

Key Features:
- Live Packet Sniffing (requires admin/root privileges)
- SQL Injection & XSS Detection
- Real-time Activity Logging
- Historical Detection Records
- Threat Breakdown & Traffic Analysis Visualizations
- Detailed Attack Information & Simulation
- Network Statistics Monitoring

Developed By:
Aakar Gupta
24BRS1321
"""
        details_text.insert(tk.END, about_info.strip())
        details_text.config(state=tk.DISABLED)
        details_text.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        ttk.Button(info_frame, text="Close", command=about_window.destroy).pack(pady=(0, 5))

    def _show_more_info(self):
        if not self.selected_intrusion_type or not self.selected_payload:
            messagebox.showwarning("No Intrusion Selected", "Please select a detected intrusion from 'Detection History' to view more information.")
            return

        intrusion_data = self.nids_engine.more_info_data.get(self.selected_intrusion_type)
        if not intrusion_data:
            messagebox.showerror("Error", f"No more information found for {self.selected_intrusion_type}.")
            return

        info_window = self._create_themed_toplevel(f"More Info: {self.selected_intrusion_type}", "750x650")
        
        text_bg = "#3C3C3C" if self.current_theme == "dark" else "#FFFFFF"
        text_fg = "#E0E0E0" if self.current_theme == "dark" else "#333333"
        log_fg_sim = "#FFD700" if self.current_theme == "dark" else "#DAA520"

        info_frame = ttk.Frame(info_window, padding=10, style='TFrame')
        info_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(info_frame, text=f"Details for: {self.selected_intrusion_type}", font=('Segoe UI', 14, 'bold'), style='Header.TLabel').pack(pady=(5, 10))
        ttk.Label(info_frame, text=f"Detected Payload (Sample): '{self.selected_payload[:100]}...'" if len(self.selected_payload) > 100 else f"Detected Payload: '{self.selected_payload}'", font=('Segoe UI', 10, 'italic'), style='TLabel').pack(anchor=tk.W, pady=(0,5))

        details_text = scrolledtext.ScrolledText(info_frame, wrap=tk.WORD, height=15, font=('Consolas', 10),
                                               background=text_bg, foreground=text_fg, relief="flat")
        
        info_content = f"""
Description: {intrusion_data['description']}

Potential Effects:
{intrusion_data['effects']}

Detection Logic:
{intrusion_data['mitigation_toc']}
"""
        details_text.insert(tk.END, info_content.strip())
        details_text.config(state=tk.DISABLED)
        details_text.pack(fill=tk.X, pady=(0, 10), expand=False)

        ttk.Label(info_frame, text="Attack Simulation:", font=('Segoe UI', 12, 'bold'), style='TLabel').pack(anchor=tk.W, pady=(5, 5))
        
        self.simulation_text = scrolledtext.ScrolledText(info_frame, wrap=tk.WORD, height=8, font=('Consolas', 9),
                                                        background=text_bg, foreground=log_fg_sim, relief="flat")
        self.simulation_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.simulation_text.config(state=tk.DISABLED)
        
        simulate_button = ttk.Button(info_frame, text="Simulate Attack Effects", 
                                     command=lambda: self._run_attack_simulation(self.selected_intrusion_type, self.selected_payload, log_fg_sim))
        simulate_button.pack(pady=(0, 10))

        ttk.Button(info_frame, text="Close", command=info_window.destroy).pack(pady=(0, 5))
    
    def _run_attack_simulation(self, intrusion_type, detected_payload, log_fg_sim):
        simulation_data = self.nids_engine.more_info_data.get(intrusion_type, {}).get("simulation")
        if not simulation_data:
            self.simulation_text.config(state=tk.NORMAL)
            self.simulation_text.delete(1.0, tk.END)
            self.simulation_text.insert(tk.END, "No simulation data available for this intrusion type.")
            self.simulation_text.config(state=tk.DISABLED)
            return

        self.simulation_text.config(state=tk.NORMAL)
        self.simulation_text.delete(1.0, tk.END)
        
        scenario = simulation_data['scenario'].replace("{payload_placeholder}", detected_payload)
        steps = [step.replace("{payload_placeholder}", detected_payload) for step in simulation_data['steps']]
        output_sample = [line.replace("{payload_placeholder}", detected_payload) for line in simulation_data['output_sample']]

        self.simulation_text.insert(tk.END, f"Scenario: {scenario}\n\n", "header")
        
        self.simulation_text.insert(tk.END, "Steps:\n")
        for step in steps:
            self.simulation_text.insert(tk.END, f"  {step}\n")
        
        self.simulation_text.insert(tk.END, "\nSimulated Output:\n")
        for line in output_sample:
            self.simulation_text.insert(tk.END, f"{line}\n", "output_sample")

        self.simulation_text.config(state=tk.DISABLED)
        self.simulation_text.tag_config("header", font=('Consolas', 10, 'bold'), foreground=log_fg_sim)
        self.simulation_text.tag_config("output_sample", foreground=log_fg_sim)


    def _show_network_info(self):
        self.network_window = self._create_themed_toplevel("Network Statistics", "900x700")
        self.network_window.protocol("WM_DELETE_WINDOW", lambda: self._stop_network_monitoring())

        network_frame = ttk.Frame(self.network_window, padding=10, style='TFrame')
        network_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(network_frame, text="Real-time Network Activity", font=('Segoe UI', 14, 'bold'), style='Header.TLabel').pack(pady=(5, 10))
        
        self.net_stats_label = ttk.Label(network_frame, text="Loading network stats...", style='TLabel')
        self.net_stats_label.pack(anchor=tk.W, pady=(0, 10))

        ttk.Label(network_frame, text="Current Interface Statistics:", font=('Segoe UI', 11, 'bold'), style='TLabel').pack(anchor=tk.W, pady=(5, 5))
        self.net_table = ttk.Treeview(network_frame, columns=("Metric", "Value"), show="headings", height=6)
        self.net_table.heading("Metric", text="Metric", anchor=tk.W)
        self.net_table.heading("Value", text="Value", anchor=tk.W)
        self.net_table.column("Metric", width=150, stretch=tk.NO)
        self.net_table.column("Value", width=250, stretch=tk.YES)
        self.net_table.pack(fill=tk.X, pady=(0, 10))

        self.net_fig, self.net_ax = plt.subplots(figsize=(7, 4))
        self.net_canvas = FigureCanvasTkAgg(self.net_fig, master=network_frame)
        self.net_canvas_widget = self.net_canvas.get_tk_widget()
        self.net_canvas_widget.pack(fill=tk.BOTH, expand=True)

        ttk.Button(network_frame, text="Close", command=lambda: self._stop_network_monitoring()).pack(pady=(10, 5))

        self.network_monitoring_active = True
        self._update_network_monitor()

    def _update_network_monitor_if_active(self):
        if self.network_monitoring_active:
            self._update_network_monitor()
        # Schedule the next check regardless of whether the window is open
        self.master.after(1000, self._update_network_monitor_if_active)

    def _update_network_monitor(self):
        if not hasattr(self, 'network_window') or not self.network_window.winfo_exists():
            self.network_monitoring_active = False # Stop if window closed
            return
            
        current_net_io = psutil.net_io_counters()
        bytes_sent_diff = (current_net_io.bytes_sent - self.last_net_io.bytes_sent) / 1024
        bytes_recv_diff = (current_net_io.bytes_recv - self.last_net_io.bytes_recv) / 1024
        self.last_net_io = current_net_io
        self.net_io_data.append((bytes_sent_diff, bytes_recv_diff))
        
        is_dark = self.current_theme == "dark"
        mpl_bg = "#3C3C3C" if is_dark else "#FFFFFF"
        mpl_text = "#E0E0E0" if is_dark else "#333333"

        for item in self.net_table.get_children():
            self.net_table.delete(item)
        
        self.net_table.insert("", tk.END, values=("Bytes Sent (Total)", f"{current_net_io.bytes_sent / (1024**2):.2f} MB"))
        self.net_table.insert("", tk.END, values=("Bytes Received (Total)", f"{current_net_io.bytes_recv / (1024**2):.2f} MB"))
        self.net_table.insert("", tk.END, values=("Packets Sent (Total)", f"{current_net_io.packets_sent}"))
        self.net_table.insert("", tk.END, values=("Packets Received (Total)", f"{current_net_io.packets_recv}"))
        self.net_table.insert("", tk.END, values=("Errors In (Total)", f"{current_net_io.errin}"))
        self.net_table.insert("", tk.END, values=("Errors Out (Total)", f"{current_net_io.errout}"))


        if len(self.net_io_data) > 1:
            times = list(range(len(self.net_io_data)))
            sent_data = [d[0] for d in self.net_io_data]
            recv_data = [d[1] for d in self.net_io_data]

            self.net_ax.clear()
            self.net_ax.plot(times, sent_data, label='Sent (KB/s)', color='orange')
            self.net_ax.plot(times, recv_data, label='Received (KB/s)', color='cyan')
            self.net_ax.legend(loc='upper left', frameon=False, labelcolor=mpl_text)
            self.net_ax.set_title("Network I/O (KB/s)", color=mpl_text)
            self.net_ax.set_ylabel("Speed (KB/s)", color=mpl_text)
            self.net_ax.set_xlabel("Time (seconds ago)", color=mpl_text)
            self.net_ax.set_facecolor(mpl_bg)
            self.net_fig.set_facecolor(mpl_bg)
            self.net_ax.tick_params(colors=mpl_text)
            for spine in self.net_ax.spines.values():
                spine.set_edgecolor(mpl_text)
            self.net_fig.tight_layout()
            self.net_canvas.draw_idle()
        
        self.net_stats_label.config(text=f"Current Up: {bytes_sent_diff:.2f} KB/s | Current Down: {bytes_recv_diff:.2f} KB/s")
        if self.network_monitoring_active:
            self.network_window.after(1000, self._update_network_monitor)
    
    def _stop_network_monitoring(self):
        self.network_monitoring_active = False
        if hasattr(self, 'network_window') and self.network_window.winfo_exists():
            self.network_window.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = NIDSApp(root)
    root.mainloop()
