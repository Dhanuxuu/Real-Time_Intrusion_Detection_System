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




