import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, Toplevel, StringVar
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import deque
from datetime import datetime
import psutil
import threading
import time
import re
import socket

from scapy.all import sniff, IP, TCP, Raw, get_if_list, get_if_addr

class SQLInjectionParser:
    def __init__(self, payload):
        self.payload = payload.strip()

    def parse(self):
        payload_lower = self.payload.lower()

        patterns_tautology = [
            r"('|%27)\s*(or|\|\|)\s*('|%27)?\d+('|%27)?\s*=\s*('|%27)?\d+('|%27)?(\s*(--|#|\/\*|\+\-\-))?",
            r"(or|\|\|)\s*\d+\s*=\s*\d+(\s*(--|#|\/\*|\+\-\-))?",
            r"(union\s+select|select\s+union)",
            r"(benchmark|sleep|pg_sleep)\s*\("
        ]

        for pattern in patterns_tautology:
            if re.search(pattern, payload_lower):
                return True

        patterns_error = [
            r"(updatexml|extractvalue|floor)\s*\(",
            r"(convert|cast)\s*\([a-zA-Z0-9_]+\s*as\s*xml\)"
        ]
        for pattern in patterns_error:
            if re.search(pattern, payload_lower):
                return True
                
        if re.search(r"('|%27)?\s*;\s*([a-zA-Z0-9_]+\s*insert|update|delete|drop|alter)", payload_lower):
             return True

        return False

class XSSParser:
    def __init__(self, payload):
        self.payload = payload.strip()

    def parse(self):
        payload_lower = self.payload.lower()

        if re.search(r"<script.*?>.*?</script.*?>", payload_lower):
            return True
        
        if re.search(r"<img[^>]+(onerror|onload)\s*=\s*['\"].*?['\"][^>]*>", payload_lower):
            return True

        if re.search(r"<(iframe|body|svg|a|div)[^>]+on[a-zA-Z]+\s*=\s*['\"].*?['\"][^>]*>", payload_lower):
            return True

        if re.search(r"&lt;script.*?&gt;.*?&lt;/script.*?&gt;", payload_lower):
            return True

        if re.search(r"(src|href)\s*=\s*['\"]?\s*data:text/html;base64,", payload_lower):
            return True
            
        if re.search(r"(href|src)\s*=\s*['\"]?\s*javascript:.*['\"]?", payload_lower):
            return True

        return False

class NIDSEngine:
    def __init__(self):
        self.parsers = {
            "SQL Injection": SQLInjectionParser,
            "XSS (Script Tag)": XSSParser
        }
        self.more_info_data = {
            "SQL Injection": {
                "description": "This attack injects malicious SQL code into database query inputs. Attackers can bypass authentication, extract sensitive data, or even modify/delete database contents.",
                "effects": "• Data Theft: Unauthorized access to sensitive database information (user credentials, financial data).\n• Data Corruption: Unauthorized modification or deletion of data, impacting data integrity.\n• Server Takeover: In severe cases, potential for remote code execution on the database server itself.",
                "mitigation": "Detection relies on identifying common SQL keywords, logic bypasses (like tautologies), error-based functions, or time-delay functions used in blind injections. Robust input validation and parameterized queries are key mitigations.",
                "simulation": {
                    "scenario": "Simulating a login bypass attack on a vulnerable web application...",
                    "steps": [
                        "1. Attacker inputs a malicious SQL payload: `{payload_placeholder}` into a login field.",
                        "2. The web application's backend attempts to construct a database query (e.g., `SELECT * FROM users WHERE username='{payload_placeholder}' AND password='...'`).",
                        "3. The injected SQL logic `OR '1'='1'` makes the condition always true, effectively bypassing the password check.",
                        "4. The database returns unauthorized records, typically the first user (e.g., 'admin')."
                    ],
                    "output_sample": [
                        "--- Original Query (Internal) ---",
                        "SELECT * FROM users WHERE username='**[input_username]**' AND password='**[input_password]**'",
                        "",
                        "--- Injected Query (Internal) ---",
                        "SELECT * FROM users WHERE username='' **OR '1'='1' --**' AND password='**[original_password]**'",
                        "  (The '--' comments out the rest of the original query)",
                        "",
                        "--- Simulated Database Response ---",
                        "QUERY EXECUTED: SELECT * FROM users WHERE username='' OR '1'='1' --' AND password='...'",
                        "RESULT: Authenticated as: 'admin'",
                        "EFFECT: Full data exposure or unauthorized access for the first matching user."
                    ]
                }
            },
            "XSS (Script Tag)": {
                "description": "Cross-Site Scripting (XSS) injects malicious client-side scripts into trusted web pages. When a victim loads the compromised page, the script executes in their browser, leading to various client-side attacks.",
                "effects": "• Session Hijacking: Stealing user session cookies, allowing the attacker to impersonate the victim.\n• Defacement: Altering the content of the web page shown to the victim.\n• Phishing: Redirecting users to malicious sites or injecting fake login forms.\n• Malware Delivery: Forcing the victim's browser to download malicious files.",
                "mitigation": "Detection involves scanning for common script tags (`<script>`), HTML entity encoded scripts (`&lt;script&gt;`), event handlers (`onerror`, `onload`), and `javascript:` URIs. Mitigation includes strict output encoding and Content Security Policy (CSP).",
                "simulation": {
                    "scenario": "Simulating a reflected XSS attack on a vulnerable web page...",
                    "steps": [
                        "1. An attacker crafts a URL containing an XSS payload (e.g., `http://vulnerable.com/search?query={payload_placeholder}`).",
                        "2. The victim clicks this link or visits the compromised page.",
                        "3. The vulnerable web server reflects the payload `{payload_placeholder}` directly into the HTML response without proper sanitization.",
                        "4. The victim's browser executes the injected script as if it were legitimate code from the website."
                    ],
                    "output_sample": [
                        "--- Simulated Browser Actions ---",
                        "[Browser] Fetches URL: `http://vulnerable.com/search?query={payload_placeholder}`",
                        "[Browser] Parses HTML response...",
                        "[Browser] DISCOVERED MALICIOUS SCRIPT TAG:",
                        "  CODE: `{payload_placeholder}`",
                        "",
                        "[Browser] EXECUTING SCRIPT...",
                        "RESULT: A JavaScript `alert('You are hacked!');` window pops up.",
                        "          (Alternatively: Browser sends victim's cookies to attacker's server: `GET /steal?cookie=...`)",
                        "          (Alternatively: Browser redirects to malicious site: `location.href='http://evil.com'`)",
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

            if packet.haslayer(Raw):
                try:
                    payload_data = packet[Raw].load.decode('utf-8', errors='ignore')
                except Exception:
                    payload_data = str(packet[Raw].load)

        if payload_data and (
            "HTTP/" in payload_data or
            "GET " in payload_data or
            "POST " in payload_data or
            "PUT " in payload_data or
            "Host: " in payload_data or
            "User-Agent: " in payload_data
        ):
            self.callback_fn(f"[{src_ip}:{sport} -> {dst_ip}:{dport}] {payload_data}")

        if self._stop_event.is_set():
            return True

    def start_sniffing(self, iface=None, filter_str="tcp and (port 80 or port 8080 or port 443)", count=0):
        print(f"Starting sniffing on {iface if iface else 'all interfaces'} with filter '{filter_str}'...")
        self._stop_event.clear()
        self.sniff_thread = threading.Thread(target=sniff, kwargs={
            "prn": self._packet_handler, 
            "store": 0, 
            "stop_filter": lambda p: self._stop_event.is_set(),
            "iface": iface,
            "filter": filter_str,
            "count": count
        })
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def stop_sniffing(self):
        if self.sniff_thread and self.sniff_thread.is_alive():
            print("Signaling sniff thread to stop...")
            self._stop_event.set()
            self.sniff_thread.join(timeout=5)
            if self.sniff_thread.is_alive():
                print("Warning: Sniff thread might still be active after timeout.")
            self.sniff_thread = None

class NIDSApp:
    def __init__(self, master):
        self.master = master
        master.title("Advanced Network Intrusion Detection System (NIDS)")
        master.geometry("1400x850")

        self.current_theme = "dark"
        self._setup_styles()
        
        self.nids_engine = NIDSEngine()
        self.intrusion_log = deque(maxlen=200)
        self.detection_counts = {"SQL Injection": 0, "XSS (Script Tag)": 0, "Benign": 0}
        self.selected_intrusion_type = None 
        self.selected_payload = None

        self.sniffer = TrafficSniffer(self._handle_sniffed_data)
        self.sniffing_active = False

        self._create_widgets()
        self._setup_graphs()
        self.toggle_theme(initial_setup=True)

        self.last_net_io_time = time.time()
        self.last_net_io = psutil.net_io_counters()
        self.net_io_data_sent = deque(maxlen=60)
        self.net_io_data_recv = deque(maxlen=60)
        self.network_monitoring_active = False
        self._update_network_monitor_if_active()

        self.master.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')

    def _configure_theme_styles(self):
        is_dark = self.current_theme == "dark"
        
        bg_color = "#212121" if is_dark else "#F5F5F5"
        panel_bg = "#303030" if is_dark else "#FFFFFF"
        text_color = "#E0E0E0" if is_dark else "#333333"
        log_bg = "#303030" if is_dark else "#FDFDFD"
        log_fg_benign = "#4CAF50" if is_dark else "#2E7D32"
        log_fg_malicious = "#EF5350" if is_dark else "#D32F2F"
        entry_field_bg = "#424242" if is_dark else "#FFFFFF"
        button_bg = "#424242" if is_dark else "#E0E0E0"
        button_fg = "#FFFFFF" if is_dark else "#333333"
        tree_field_bg = "#424242" if is_dark else "#FFFFFF"
        tree_fg = "#E0E0E0" if is_dark else "#333333"
        header_fg = "#FFFFFF" if is_dark else "#111111"
        footer_fg = "#9E9E9E" if is_dark else "#616161"
        tree_selected_bg = "#1976D2" if is_dark else "#BBDEFB"

        self.master.configure(bg=bg_color)
        self.style.configure('TFrame', background=bg_color)
        self.style.configure('Dark.TLabelframe', background=panel_bg, foreground=text_color, font=('Segoe UI', 12, 'bold'))
        self.style.configure('Dark.TLabelframe.Label', background=panel_bg, foreground=text_color, font=('Segoe UI', 12, 'bold'))
        self.style.configure('TLabel', background=panel_bg, foreground=text_color, font=('Segoe UI', 10))
        self.style.configure('Header.TLabel', background=bg_color, foreground=header_fg, font=('Segoe UI', 20, 'bold'))
        self.style.configure('Footer.TLabel', background=bg_color, foreground=footer_fg, font=('Segoe UI', 8))
        self.style.configure('TButton', background=button_bg, foreground=button_fg, font=('Segoe UI', 10, 'bold'), borderwidth=0)
        self.style.map('TButton', background=[('active', '#616161' if is_dark else '#CCCCCC')])
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
            self.current_theme = "light" if self.current_theme == "dark" else "dark"
            self.theme_button.config(text="Dark Mode" if self.current_theme == "light" else "Light Mode")
        self._configure_theme_styles()

    def _create_widgets(self):
        header_frame = ttk.Frame(self.master, style='TFrame')
        header_frame.pack(fill=tk.X, pady=(10, 5), padx=20)
        ttk.Label(header_frame, text="Advanced Network Intrusion Detection System (NIDS)", style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 20))
        
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

        self.sniff_control_frame = ttk.LabelFrame(self.left_panel, text="Live Traffic Analysis", style="Dark.TLabelframe", padding="10")
        self.sniff_control_frame.pack(fill=tk.X, pady=10)

        ttk.Label(self.sniff_control_frame, text="Select Interface:", style='TLabel').pack(anchor=tk.W, pady=(0, 5))
        
        interfaces = get_if_list()
        self.iface_combobox_var = StringVar(self.sniff_control_frame)
        self.iface_combobox = ttk.Combobox(self.sniff_control_frame, textvariable=self.iface_combobox_var, values=interfaces, width=37, font=('Segoe UI', 10))
        if interfaces:
            self.iface_combobox.set(interfaces[0])
        self.iface_combobox.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(self.sniff_control_frame, text="Or Target Address (IP/URL/CIDR):", style='TLabel').pack(anchor=tk.W, pady=(5, 5))
        self.target_address_entry = ttk.Entry(self.sniff_control_frame, width=50, font=('Segoe UI', 10))
        self.target_address_entry.pack(fill=tk.X, pady=(0, 10))
        
        self.start_sniff_button = ttk.Button(self.sniff_control_frame, text="Start Sniffing", command=self._start_sniffing)
        self.start_sniff_button.pack(side=tk.LEFT, expand=True, padx=(0, 5))
        self.stop_sniff_button = ttk.Button(self.sniff_control_frame, text="Stop Sniffing", command=self._stop_sniffing, state=tk.DISABLED)
        self.stop_sniff_button.pack(side=tk.RIGHT, expand=True, padx=(5, 0))
        
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

        ttk.Label(self.master, text="NIDS Project - Developed for Cybersecurity Monitoring | Name: Aakar Gupta", style="Footer.TLabel").pack(side=tk.BOTTOM, pady=(10, 5))

    def _on_closing(self):
        if self.sniffing_active:
            self._stop_sniffing()
        if self.network_monitoring_active:
            self._stop_network_monitoring()
        self.master.destroy()

    def _start_sniffing(self):
        if not self.sniffing_active:
            iface = self.iface_combobox.get().strip()
            target_address = self.target_address_entry.get().strip()
            
            if not iface:
                messagebox.showwarning("Interface Not Selected", "Please select a network interface to start sniffing.")
                return

            filter_str = "tcp and (port 80 or port 8080 or port 443)"
            
            if target_address:
                try:
                    if '/' in target_address:
                        filter_str += f" and net {target_address}"
                    elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_address):
                        filter_str += f" and host {target_address}"
                    else:
                        ip_address = socket.gethostbyname(target_address)
                        filter_str += f" and host {ip_address}"
                    self._log_message(f"Targeting traffic for: {target_address} (Resolved to {ip_address if 'ip_address' in locals() else target_address})", "green")
                except socket.gaierror:
                    messagebox.showerror("Invalid Address", f"Could not resolve or parse target address: {target_address}")
                    self._log_message(f"Error: Invalid target address '{target_address}'", "red")
                    return
                except Exception as e:
                    messagebox.showerror("Filter Error", f"Error constructing filter for {target_address}: {e}")
                    self._log_message(f"Error constructing filter: {e}", "red")
                    return

            try:
                self.sniffer.start_sniffing(iface=iface, filter_str=filter_str)
                self.sniffing_active = True
                self.start_sniff_button.config(state=tk.DISABLED)
                self.stop_sniff_button.config(state=tk.NORMAL)
                self._log_message(f"Live sniffing started on interface: {iface} with filter '{filter_str}'...", "green")
            except Exception as e:
                messagebox.showerror("Sniffing Error", f"Failed to start sniffing on '{iface}': {e}\n\n"
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
        self.master.after(0, self._process_sniffed_payload, full_packet_info)

    def _process_sniffed_payload(self, full_packet_info):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        parts = full_packet_info.split("] ", 1)
        connection_info = parts[0][1:]
        payload_data = parts[1] if len(parts) > 1 else ""

        src_dest_parts = connection_info.split(" -> ")
        source = src_dest_parts[0] if len(src_dest_parts) > 0 else "N/A"
        destination = src_dest_parts[1] if len(src_dest_parts) > 1 else "N/A"

        detected_types = self.nids_engine.analyze_payload(payload_data)

        payload_sample = payload_data.replace('\n', '\\n').replace('\r', '\\r')
        if len(payload_sample) > 50:
            payload_sample = payload_sample[:47] + "..."

        if detected_types:
            self._log_message(f"[{now}] 🚨 INTRUSION DETECTED: {connection_info} -> '{payload_sample}'", "red")
            self.intrusion_log.append({
                "time": now, 
                "source": source,
                "destination": destination,
                "payload": payload_data,
                "payload_sample": payload_sample,
                "types": detected_types
            })
            for d_type in detected_types:
                self.detection_counts[d_type] += 1
        else:
            if payload_data.strip():
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
        index = self.tree.get_children().index(selected_item)
        actual_log_index = len(self.intrusion_log) - 1 - index 
        log_entry = self.intrusion_log[actual_log_index]

        self.selected_intrusion_type = log_entry['types'][0] if log_entry['types'] else None
        self.selected_payload = log_entry['payload']
        
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
            self._log_message(f"[{now}] 🚨 INTRUSION DETECTED (Manual): '{payload_sample}'", "red")
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
            self._log_message(f"[{now}] ✅ Benign Payload (Manual): '{payload_sample}'", "green")
            self.detection_counts["Benign"] += 1
        
        self._update_dashboard()

    def _setup_graphs(self):
        self.bar_fig, self.bar_ax = plt.subplots(figsize=(6.5, 4.5)) 
        self.pie_fig, self.pie_ax = plt.subplots(figsize=(6.5, 4.5))
        self.bar_canvas = FigureCanvasTkAgg(self.bar_fig, master=self.bar_graph_frame)
        self.bar_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        self.pie_canvas = FigureCanvasTkAgg(self.pie_fig, master=self.pie_chart_frame)
        self.pie_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def _update_graphs(self):
        is_dark = self.current_theme == "dark"
        mpl_bg = "#303030" if is_dark else "#FFFFFF"
        mpl_text = "#E0E0E0" if is_dark else "#333333"
        pie_colors = ['#4CAF50', '#EF5350'] if is_dark else ['#66BB6A', '#E53935']
        bar_colors = ['#1E88E5', '#FFB300'] if is_dark else ['#2196F3', '#FFC107']

        self.bar_ax.clear()
        self.bar_fig.set_facecolor(mpl_bg)
        self.bar_ax.set_facecolor(mpl_bg)
        bar_labels = [k for k in self.detection_counts if k != "Benign"]
        bar_values = [self.detection_counts[k] for k in bar_labels]
        bars = self.bar_ax.bar(bar_labels, bar_values, color=bar_colors)
        self.bar_ax.set_title("Threat Detections", color=mpl_text, fontsize=10)
        self.bar_ax.set_ylabel("Count", color=mpl_text, fontsize=8)
        self.bar_ax.tick_params(axis='x', colors=mpl_text, labelsize=7, rotation=15)
        self.bar_ax.tick_params(axis='y', colors=mpl_text, labelsize=7)
        self.bar_ax.set_ylim(bottom=0, top=max(1, max(bar_values, default=0) * 1.1))
        for spine in self.bar_ax.spines.values():
            spine.set_edgecolor(mpl_text)
        for bar in bars:
            yval = bar.get_height()
            text_y_position = max(0.1, yval * 0.5) if yval > 0 else 0.1
            self.bar_ax.text(bar.get_x() + bar.get_width()/2.0, text_y_position, int(yval), ha='center', va='center', color=mpl_text, fontweight='bold', fontsize=7)
        
        self.bar_fig.subplots_adjust(bottom=0.2, top=0.9, left=0.15, right=0.95)
        self.bar_canvas.draw_idle()
        
        self.pie_ax.clear()
        self.pie_fig.set_facecolor(mpl_bg)
        total_intrusions = sum(self.detection_counts[k] for k in self.detection_counts if k != "Benign")
        pie_labels = ['Benign', 'Malicious']
        pie_values = [self.detection_counts['Benign'], total_intrusions]
        explode = (0, 0.1) if total_intrusions > 0 else (0, 0)
        
        if sum(pie_values) > 0:
            self.pie_ax.pie(pie_values, labels=pie_labels, autopct='%1.1f%%', startangle=140, colors=pie_colors, explode=explode, textprops={'color': mpl_text, 'fontweight': 'bold', 'fontsize': 8})
        else:
            self.pie_ax.pie([1], labels=['No Data'], colors=['#555555'], textprops={'color': mpl_text, 'fontsize': 8})
        self.pie_ax.set_title("Traffic Classification", color=mpl_text, fontsize=10)
        self.pie_fig.subplots_adjust(bottom=0.1, top=0.9, left=0.1, right=0.9)
        self.pie_canvas.draw_idle()

    def _create_themed_toplevel(self, title, geometry):
        window = Toplevel(self.master)
        window.title(title)
        window.geometry(geometry)
        window.grab_set()
        window.transient(self.master)
        bg = "#212121" if self.current_theme == "dark" else "#F5F5F5"
        window.configure(bg=bg)
        return window

    def _show_about_info(self):
        about_window = self._create_themed_toplevel("About Advanced NIDS", "550x380")
        
        text_bg = "#303030" if self.current_theme == "dark" else "#FFFFFF"
        text_fg = "#E0E0E0" if self.current_theme == "dark" else "#333333"

        info_frame = ttk.Frame(about_window, padding=20, style='TFrame')
        info_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(info_frame, text="About This Advanced NIDS Application", font=('Segoe UI', 14, 'bold'), style='Header.TLabel').pack(pady=(5, 15))

        details_text = tk.Text(info_frame, wrap=tk.WORD, font=('Segoe UI', 10),
                               bg=text_bg, fg=text_fg, relief="flat", borderwidth=0)
        about_info = """
This Advanced Network Intrusion Detection System (NIDS) provides sophisticated real-time monitoring and analysis of network traffic for cybersecurity threats.

It utilizes robust signature-based detection mechanisms to identify critical web vulnerabilities such as SQL Injection and Cross-Site Scripting (XSS) within live network payloads. The system offers a dynamic, user-friendly dashboard for visual insights, a comprehensive activity log, and interactive attack simulations to vividly demonstrate potential impacts.

Key Features:
- Real-time Packet Sniffing (requires admin/root privileges)
- Enhanced SQL Injection & XSS Detection Logic
- Dynamic Activity Logging and Historical Records
- Visual Threat Breakdown & Traffic Classification
- Interactive Attack Simulation for Educational Insight
- Live Network Interface Statistics Monitoring
- Professional User Interface with Dark/Light Theme Support

Developed as a project for advanced cybersecurity monitoring.
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

        info_window = self._create_themed_toplevel(f"More Info: {self.selected_intrusion_type}", "800x700")
        
        text_bg = "#303030" if self.current_theme == "dark" else "#FFFFFF"
        text_fg = "#E0E0E0" if self.current_theme == "dark" else "#333333"
        log_fg_sim_normal = "#90CAF9" if self.current_theme == "dark" else "#2196F3"
        log_fg_sim_output = "#FFD700" if self.current_theme == "dark" else "#DAA520"
        log_fg_sim_malicious = "#EF5350" if self.current_theme == "dark" else "#D32F2F"

        info_frame = ttk.Frame(info_window, padding=10, style='TFrame')
        info_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(info_frame, text=f"Details for: {self.selected_intrusion_type}", font=('Segoe UI', 14, 'bold'), style='Header.TLabel').pack(pady=(5, 10))
        
        payload_display = self.selected_payload if len(self.selected_payload) <= 200 else self.selected_payload[:197] + "..."
        ttk.Label(info_frame, text=f"Detected Payload (Truncated): '{payload_display.replace('\n', '\\n').replace('\r', '\\r')}'", font=('Segoe UI', 10, 'italic'), style='TLabel', wraplength=750, justify=tk.LEFT).pack(anchor=tk.W, pady=(0,5))

        details_text = scrolledtext.ScrolledText(info_frame, wrap=tk.WORD, height=12, font=('Consolas', 10),
                                               background=text_bg, foreground=text_fg, relief="flat")
        
        info_content = f"""
Description: {intrusion_data['description']}

Potential Effects:
{intrusion_data['effects']}

Detection Logic:
{intrusion_data['mitigation']}
"""
        details_text.insert(tk.END, info_content.strip())
        details_text.config(state=tk.DISABLED)
        details_text.pack(fill=tk.X, pady=(0, 10), expand=False)

        ttk.Label(info_frame, text="Attack Simulation:", font=('Segoe UI', 12, 'bold'), style='TLabel').pack(anchor=tk.W, pady=(5, 5))
        
        self.simulation_text = scrolledtext.ScrolledText(info_frame, wrap=tk.WORD, height=10, font=('Consolas', 9),
                                                        background=text_bg, foreground=log_fg_sim_normal, relief="flat")
        self.simulation_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.simulation_text.config(state=tk.DISABLED)
        
        simulate_button = ttk.Button(info_frame, text="Run Attack Simulation", 
                                     command=lambda: threading.Thread(target=self._run_attack_simulation, 
                                                                       args=(simulate_button, self.selected_intrusion_type, self.selected_payload, log_fg_sim_normal, log_fg_sim_output, log_fg_sim_malicious), 
                                                                       daemon=True).start())
        simulate_button.pack(pady=(0, 10))

        ttk.Button(info_frame, text="Close", command=info_window.destroy).pack(pady=(0, 5))
    
    def _update_simulation_text(self, text, tag=None):
        self.simulation_text.config(state=tk.NORMAL)
        self.simulation_text.insert(tk.END, text, tag)
        self.simulation_text.yview(tk.END)
        self.simulation_text.config(state=tk.DISABLED)
        self.master.update_idletasks()

    def _run_attack_simulation(self, button, intrusion_type, detected_payload, normal_fg, output_fg, malicious_fg):
        self.master.after(0, lambda: button.config(state=tk.DISABLED))
        
        self.master.after(0, lambda: self.simulation_text.config(state=tk.NORMAL))
        self.master.after(0, lambda: self.simulation_text.delete(1.0, tk.END))
        self.master.after(0, lambda: self.simulation_text.config(state=tk.DISABLED))
        
        simulation_data = self.nids_engine.more_info_data.get(intrusion_type, {}).get("simulation")
        if not simulation_data:
            self.master.after(0, lambda: self._update_simulation_text("No simulation data available for this intrusion type.\n", normal_fg))
            self.master.after(0, lambda: button.config(state=tk.NORMAL))
            return

        scenario = simulation_data['scenario'].replace("{payload_placeholder}", detected_payload)
        steps_template = simulation_data['steps']
        output_sample_template = simulation_data['output_sample']

        self.master.after(0, lambda: self._update_simulation_text(f"Scenario: {scenario}\n\n", "header_sim"))
        self.master.after(0, lambda: self.simulation_text.tag_config("header_sim", font=('Consolas', 10, 'bold'), foreground=normal_fg))
        time.sleep(1)

        self.master.after(0, lambda: self._update_simulation_text("Steps:\n", normal_fg))
        for i, step_template in enumerate(steps_template):
            step = step_template.replace("{payload_placeholder}", detected_payload)
            self.master.after(0, lambda s=step: self._update_simulation_text(f"  {s}\n", normal_fg))
            time.sleep(1.5)

        self.master.after(0, lambda: self._update_simulation_text("\nSimulated Output:\n", "header_sim"))
        time.sleep(1)

        for line_template in output_sample_template:
            line = line_template.replace("{payload_placeholder}", detected_payload)
            tag = output_fg
            if "EFFECT:" in line or "MALICIOUS" in line or "HACKED" in line or "UNAUTHORIZED" in line:
                tag = malicious_fg
            self.master.after(0, lambda l=line, t=tag: self._update_simulation_text(f"{l}\n", t))
            time.sleep(0.8)
        
        self.master.after(0, lambda: self._update_simulation_text("\n--- Simulation Complete ---\n", normal_fg))
        self.master.after(0, lambda: button.config(state=tk.NORMAL))

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
            pass 
        else:
            self.master.after(1000, self._update_network_monitor_if_active)

    def _update_network_monitor(self):
        if not hasattr(self, 'network_window') or not self.network_window.winfo_exists():
            self.network_monitoring_active = False 
            return
            
        current_time = time.time()
        time_diff = current_time - self.last_net_io_time
        
        current_net_io = psutil.net_io_counters()
        
        if time_diff > 0:
            bytes_sent_diff = (current_net_io.bytes_sent - self.last_net_io.bytes_sent) / time_diff / 1024
            bytes_recv_diff = (current_net_io.bytes_recv - self.last_net_io.bytes_recv) / time_diff / 1024
        else:
            bytes_sent_diff = 0
            bytes_recv_diff = 0

        self.last_net_io = current_net_io
        self.last_net_io_time = current_time

        self.net_io_data_sent.append(bytes_sent_diff)
        self.net_io_data_recv.append(bytes_recv_diff)
        
        is_dark = self.current_theme == "dark"
        mpl_bg = "#303030" if is_dark else "#FFFFFF"
        mpl_text = "#E0E0E0" if is_dark else "#333333"

        for item in self.net_table.get_children():
            self.net_table.delete(item)
        
        self.net_table.insert("", tk.END, values=("Interface Name", f"{self.iface_combobox.get() or 'All Active'}"))
        self.net_table.insert("", tk.END, values=("Bytes Sent (Total)", f"{current_net_io.bytes_sent / (1024**2):.2f} MB"))
        self.net_table.insert("", tk.END, values=("Bytes Received (Total)", f"{current_net_io.bytes_recv / (1024**2):.2f} MB"))
        self.net_table.insert("", tk.END, values=("Packets Sent (Total)", f"{current_net_io.packets_sent}"))
        self.net_table.insert("", tk.END, values=("Packets Received (Total)", f"{current_net_io.packets_recv}"))
        self.net_table.insert("", tk.END, values=("Errors In (Total)", f"{current_net_io.errin}"))
        self.net_table.insert("", tk.END, values=("Errors Out (Total)", f"{current_net_io.errout}"))

        if len(self.net_io_data_sent) > 0:
            times = list(range(len(self.net_io_data_sent)))
            
            self.net_ax.clear()
            self.net_ax.plot(times, self.net_io_data_sent, label='Sent (KB/s)', color='#FFC107')
            self.net_ax.plot(times, self.net_io_data_recv, label='Received (KB/s)', color='#2196F3')
            self.net_ax.legend(loc='upper left', frameon=False, labelcolor=mpl_text)
            self.net_ax.set_title("Network I/O (KB/s)", color=mpl_text, fontsize=10)
            self.net_ax.set_ylabel("Speed (KB/s)", color=mpl_text, fontsize=8)
            self.net_ax.set_xlabel("Time Elapsed (seconds)", color=mpl_text, fontsize=8) # Modified x-axis label
            self.net_ax.set_facecolor(mpl_bg)
            self.net_fig.set_facecolor(mpl_bg)
            self.net_ax.tick_params(colors=mpl_text, labelsize=7)
            self.net_ax.set_ylim(bottom=0)
            for spine in self.net_ax.spines.values():
                spine.set_edgecolor(mpl_text)
            self.net_fig.tight_layout()
            self.net_canvas.draw_idle()
        
        self.net_stats_label.config(text=f"Current Upload: {bytes_sent_diff:.2f} KB/s | Current Download: {bytes_recv_diff:.2f} KB/s")
        
        self.network_window.after(200, self._update_network_monitor)
    
    def _stop_network_monitoring(self):
        self.network_monitoring_active = False
        if hasattr(self, 'network_window') and self.network_window.winfo_exists():
            self.network_window.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = NIDSApp(root)
    root.mainloop()
