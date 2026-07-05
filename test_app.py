from scapy.all import IP, TCP
# Pull class configurations directly from your working project modules
from PacketCapture import PacketCapture
from Analysis import TrafficAnalyzer
from Detection import DetectionEngine
from Alert import AlertSystem

class MockIntrusionDetectionSystem:
    """A variation of your IDS that runs safely without binding to a physical hardware card"""
    def __init__(self):
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()

def test_ids():
    # Setup baseline mock execution constraints
    test_packets = [
        # Normal traffic simulations
        IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="A"),
        IP(src="192.168.1.3", dst="192.168.1.4") / TCP(sport=1235, dport=443, flags="P"),

        # SYN flood packet signatures (Notice window size is > 1024, so they bypass port scan rules)
        IP(src="10.0.0.1", dst="192.168.1.2") / TCP(sport=5678, dport=80, flags="S", window=2048),
        IP(src="10.0.0.2", dst="192.168.1.2") / TCP(sport=5679, dport=80, flags="S", window=2048),
        IP(src="10.0.0.3", dst="192.168.1.2") / TCP(sport=5680, dport=80, flags="S", window=2048),

        # Multi-destination sweeping network scans
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=22, flags="S", window=512),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=23, flags="S", window=512),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=25, flags="S", window=512),
    ]

    ids = MockIntrusionDetectionSystem()

    print("[*] Starting Local Simulation Test Mode...")
    for i, packet in enumerate(test_packets, 1):
        # Inject standard time properties onto the test metrics
        packet.time = float(i) 
        print(f"\nProcessing packet {i}: {packet.summary()}")

        features = ids.traffic_analyzer.analyze_packet(packet)

        if features:
            # 1. Safely extract IP data from the packet structure
            ip_src = packet[IP].src if IP in packet else None
            ip_dst = packet[IP].dst if IP in packet else None
            
            # 2. Make exactly ONE engine call passing all parameters
            threats = ids.detection_engine.detect_threats(features, ip_src=ip_src, ip_dst=ip_dst)
            
            # 3. Handle and print the output evaluations cleanly
            if threats:
                print(f"[!] Threat Detected: {threats}")
            else:
                print("[+] Safe Packet: Passed Evaluation Verification Check.")
        else:
            print("[-] Parsing Engine Dropped Data: Packet does not meet tracking scope.")

    print("\n[+] Architecture Verification Simulation Runs Finished Successfully.")

if __name__ == "__main__":
    test_ids()
