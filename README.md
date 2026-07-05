# Network Intrusion Detection System (NIDS)

A Python-based localized Network Intrusion Detection System (NIDS). The application captures live network packets via **Scapy**, extracts granular network flow statistics, and pairs rule-based tracking models with a **Scikit-Learn (Isolation Forest)** classifier engine to identify security anomalies like SYN Floods and Port Scans.

## 📁 Project Directory Layout

```text
IDS/
│
├── .venv/                  # Local project virtual environment
├── app.py                  # Main entry point for live interface packet captures
├── test_app.py             # Sandbox offline simulation testing module
├── PacketCapture.py        # Threaded network packet sniffing driver
├── Analysis.py             # Traffic statistical feature extraction engine
├── Detection.py            # Hybrid ML / Rule-based threat evaluator
├── Alert.py                # Logging system and security notification script
└── requirements.txt        # Frozen dependency specification mapping
```

## 🛠️ Windows System Requirements

Because this system runs on Windows, your network hardware interface needs low-level kernel drivers to engage in packet analysis:

1. **Npcap**: Download and install [Npcap](https://npcap.com). Make sure you tick the check box that says *"Install Npcap in WinPcap API-compatible Mode"* during the installation wizard setup.
2. **Python Interpreter**: Python 3.12+ (packaged cleanly via Conda-forge/Miniforge runtime systems).

## 🚀 Environment Configuration

Execute these setup procedures using an open VScode terminal inside your project working root directory 

### 1. Initialize Virtual Environment
```powershell
python -m venv .venv
#select a suitable interpreter and activate the virtual environment
    #ctrl + shift + p
    #select a suitable environment from the list (...workspace)
    #Kill the current terminal and open a new terminal or enter the below command,
.\.venv\Scripts\Activate.ps1
```

### 2. Synchronize Verified Project Requirements
Install the exact framework package versions frozen by your operational deployment pipeline:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 3. Verify Hardware Adapter Mapping
Windows labels local network hardware components with descriptive strings rather than generic names like `eth0`. Check your machine's exact adapter descriptions using this terminal shortcut:
```powershell
.\.venv\Scripts\python.exe -c "from scapy.all import show_interfaces; show_interfaces()"
```
*Note: Your device uses the wireless description **`Realtek RTL8821CE Adapter`**. This string has been assigned inside `app.py` as your target capturing parameter interface default value.*

---

## 💻 Execution Routines

### Phase A: Architecture Simulation Test (Safe Offline Verification)
To validate the statistical performance evaluation math and confirm your hybrid threat logic parses state triggers without crashing your environment, run the simulated text suite:
```powershell
.\.venv\Scripts\python.exe test_app.py
```
This loop runs entirely in-memory, mocking normal records, traffic patterns, resource probing sweeps, and dense network anomalies.

### Phase B: Live Network Intrusion Detection (Production Mode)
**Crucial Requirement:** Listening to local adapter components requires administrator privileges. Close any regular terminal windows, open a new PowerShell prompt using **"Run as Administrator"**, change directory to your folder, and launch:
```powershell
.\.venv\Scripts\python.exe app.py
```

---

## 📊 Monitored Data Vector Specification
The feature analysis script processes incoming raw bytes into 2D matrices formatted for Scikit-Learn models:

| Extraction Metric | Type | Objective Property Monitored |
| :--- | :--- | :--- |
| `packet_size` | Integer | Total numeric byte size of the network packet payload |
| `flow_duration` | Float | Active transmission duration window delta for the specific communication session |
| `packet_rate` | Float | Evaluated frequency of packet densities against overall session duration thresholds |
| `byte_rate` | Float | Overall density volume metrics tracing raw bandwidth consumption ratios |
| `tcp_flags` | Integer | Binary bitmask integer representation translating raw header properties (e.g., SYN, ACK, PUSH) |
| `window_size` | Integer | Dynamic structural allocation bounds set over individual network socket connections |


# Network Intrusion Detection System (NIDS) — Project Retrospective

A comprehensive overview of my experience building a real-time network security monitor, highlighting the technical stack, core learning outcomes, troubleshooting victories, and roadmap for future iterations.

---

## 🛠️ Technical Stack
* **Programming Language:** Python 3.x
* **Network Analysis Engine:** Scapy (Raw packet manipulation and injection framework)
* **Data Processing:** Python Standard Library (`collections.defaultdict`, `threading`, `socket`)
* **Packet Capture Driver:** Npcap (Windows packet interception architecture)
* **Development Environment:** VS Code, Git, Python Virtual Environments (`venv`)

---

## 💡 Skills & Core Concepts Learned
* **Low-Level Protocol Parsing:** Gained a deep understanding of the OSI model by capturing, inspecting, and manipulating raw Layer 3 (IP) and Layer 4 (TCP/UDP) network packets.
* **Stateful Flow Tracking:** Developed structures to compute real-time connection telemetry, tracking live variables like active packet counts, bandwidth consumption (byte counts), and flow durations.
* **Hermetic Environment Isolation:** Mastered dependency management using isolated local virtual environments (`.venv`), ensuring seamless deployment via precise version manifests (`requirements.txt`).
* **Repository Defensive Hygiene:** Implemented robust `.gitignore` rules to enforce good operational security (OpSec)—safeguarding proprietary directory structures, local network credentials, and system hardware specifications from public exposure.

---

## ⚠️ Challenges & Troubleshooting Breakthroughs
* **Interpreter Path Alignment:** Diagnosed and resolved configuration conflicts where global packet managers (Miniforge/Conda layers) overrode the project's local `.venv` environment context inside VS Code.
* **Windows Network Interface Constraints:** Overcame OS-level execution blocks on raw socket listening under Windows 10 by deploying the Npcap driver in WinPcap-compatible mode to cleanly interface with the physical hardware card.
* **Persistent Daemon Cleanup:** Refactored infinite listening structures (`while True:` loops) to listen for keyboard interrupts and process lifecycle shutdowns cleanly without leaving active network ports hanging open.

---

## 🔮 Future Improvements
1. **Anomaly Detection Thresholds:** Integrate programmatic detection logic to automatically flag suspicious traffic behavior, such as rapid port scans or potential Denial of Service (DoS) spikes.
2. **Asynchronous Packet Queueing:** Transition pipeline intake from synchronous loop frameworks to asynchronous architectures (`asyncio`) to safely buffer incoming streams under high-traffic network loads.
3. **Live UI Dashboard:** Build an interactive terminal dashboard or local web-based telemetry display to output flowing network metrics into visual graphs in real time.


