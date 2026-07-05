import numpy as np
from sklearn.ensemble import IsolationForest
from collections import defaultdict

class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(contamination=0.01, random_state=42)
        self.is_trained = False
        
        # Stateful trackers to catch distributed floods
        self.syn_flood_tracker = defaultdict(int)  # Tracks SYN packets sent to a target IP

    def train_baseline(self, baseline_data):
        X = np.array(baseline_data)
        self.anomaly_detector.fit(X)
        self.is_trained = True
        print("[+] IsolationForest baseline generation completed.")

    def detect_threats(self, features, ip_src=None, ip_dst=None):
        threats_found = []

        # 1. Rule-Based Threat Analysis
        # Check if the packet has a SYN flag (SYN flag value is 2)
        if features['tcp_flags'] == 2:
            # Threat Type A: Port Scan Detection (based on small window sizes / patterns)
            if features['window_size'] < 1024:
                threats_found.append("Potential Malicious Resource Probing")
            
            # Threat Type B: Statefully track SYN Floods targeting an IP
            if ip_dst:
                self.syn_flood_tracker[ip_dst] += 1
                # If a single destination IP receives more than 2 SYN packets in this test window
                if self.syn_flood_tracker[ip_dst] > 2:
                    threats_found.append(f"SYN Flood Attack Detected Targeting {ip_dst}")

        if features['packet_rate'] > 100.0:
            threats_found.append("High Volume Rate Threshold Violation")

        # 2. Machine Learning Anomaly Detection Pipeline
        if self.is_trained:
            feature_vector = np.array([[ 
                features['packet_size'],
                features['flow_duration'],
                features['packet_rate'],
                features['byte_rate'],
                features['tcp_flags'],
                features['window_size']
            ]])
            
            score = self.anomaly_detector.score_samples(feature_vector)
            if score < -0.1:
                threats_found.append(f"ML Anomaly Deviation Event (Score: {score:.3f})")
        
        return threats_found if threats_found else None
