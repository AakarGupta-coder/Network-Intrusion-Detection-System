# 🛡️ Sentinel — Live Network Intrusion Detection System

> Analyze. Detect. Defend — Real-time Network Security Monitoring.

**Sentinel** is a full-fledged Network Intrusion Detection System (NIDS) with a modern, interactive dashboard built entirely in Python. It captures and analyzes live network traffic to identify common web-based threats like **SQL Injection** and **Cross-Site Scripting (XSS)** using a sophisticated, signature-based detection engine.

---

## 🌌 Key Features

### 📡 Live Network Sniffing
- Captures live network packets using **Scapy**.
- Filters traffic to focus on relevant protocols (HTTP/HTTPS).
- Allows monitoring of a specific network interface or targeting a specific IP address/URL.
- **Start/Stop controls** for on-demand monitoring.

### 🎯 Signature-Based Threat Detection
- **Multi-threat analysis** for SQL Injection and XSS vulnerabilities.
- **Advanced parsing logic** using regular expressions to identify a wide range of attack variations.
- Real-time classification of traffic as "Malicious" or "Benign."

### 🖥️ Interactive Dashboard
- **Live Activity Log** with color-coded alerts for instant threat awareness.
- **Detection History** table to review past incidents with source/destination details.
- **Animated graphs** powered by **Matplotlib** showing threat breakdowns and overall traffic classification.
- **Live "Speedometer"** displaying current upload and download speeds.

### 🔬 In-Depth Analysis & Simulation
- Select any detected intrusion to enable the "More Info" feature.
- Displays detailed information on the specific threat, including its effects and mitigation strategies.
- Features a **pseudo-real-time attack simulation** that visually demonstrates the step-by-step impact of the detected payload.

### ⚙️ Professional UI/UX
- Sleek, modern interface with **Light and Dark mode** support.
- Responsive layout that adapts to different window sizes.
- Detailed "Network Info" window with live graphs and statistics.
- **Splash screen** with a loading animation on startup.

---

## 🌐 Tech Stack

| Layer | Technologies Used |
|---|---|
| **Core Application** | Python 3.x |
| **GUI Framework** | Tkinter, ttk (for modern widgets) |
| **Packet Sniffing** | Scapy |
| **Data Visualization** | Matplotlib |
| **System Monitoring** | psutil |
| **Detection Logic** | Regular Expressions (re module) |
| **Concurrency** | threading |

---

## 🗂️ Project Structure

Since this is a single-file application, the structure is contained within the `main.py` script. The key classes are:
```python
main.py
├── class SQLInjectionParser()  # Detection logic for SQLi
├── class XSSParser()           # Detection logic for XSS
├── class NIDSEngine()          # Manages parsers and threat data
├── class TrafficSniffer()      # Handles packet capture with Scapy
└── class NIDSApp()             # Main Tkinter application class
```

---

## 🛠️ Getting Started

### 📦 Prerequisites

Make sure you have the following installed:
- Python (v3.8 or above)
- pip
- Git

**Important:** This application requires administrator/root privileges to capture network packets.

### 🚀 Application Setup

1.  Clone the repository:
    ```bash
    git clone <your-repository-url>
    cd <your-repository-directory>
    ```

2.  Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```
    *(You will need to create a `requirements.txt` file with the following content):*
    ```
    matplotlib
    psutil
    scapy
    ```

3.  **Install Npcap (Windows Users Only):**
    * Download and install Npcap from [https://nmap.org/npcap/](https://nmap.org/npcap/).
    * During installation, make sure to check the box for **"Install Npcap in WinPcap API-compatible Mode."**

4.  Run the application with administrator/root privileges:

    **On Windows:**
    - Open Command Prompt or PowerShell **as Administrator**.
    - Navigate to the project directory and run:
    ```bash
    python main.py
    ```

    **On Linux/macOS:**
    ```bash
    sudo python main.py
    ```

> The application dashboard will launch after a brief startup animation.

---

## 🧪 How to Use

1.  **Select a Network Interface** from the dropdown menu.
2.  Optionally, enter a specific **Target Address** (like `google.com` or an IP) to filter traffic.
3.  Click **"Start Sniffing"** to begin live analysis.
4.  Generate some network traffic (e.g., browse the web).
5.  To test detections, use the **"Manual Payload Analysis"** section with known malicious strings.
6.  Click on any detected intrusion in the **"Detection History"** to enable the **"More Info"** button and view the detailed analysis and simulation.

---

## 🤝 Contributing

Contributions, ideas, and suggestions are welcome! If you find a bug or have an idea for a feature, feel free to open an issue or create a pull request.

---

## 📄 License

This project is for educational purposes. Unauthorized use for attacking targets is strictly prohibited.
© 2025 Aakar Gupta. All rights reserved.

---

## 👨‍💻 Developer

**Aakar Gupta**, CS Engineering Student
> *"Building secure systems by understanding how they break."*
