import pyshark
import json
import asyncio  # Add this import at the top of your file
from collections import defaultdict

# --- Configuration & Baselines ---
PCAP_FILE = "ics_traffic_capture.pcap"
HMI_IP = "192.168.1.10"

# Standard Modbus Function Codes (1 to 43 are generally standard)
VALID_FUNCTION_CODES = set(range(1, 44))
# State-altering Write Function Codes (0x05, 0x06, 0x0F, 0x10)
WRITE_FUNCTION_CODES = {5, 6, 15, 16}

def analyze_pcap(file_path):
    print(f"[*] Loading PCAP file: {file_path}...")
    
    try:
        # Load the capture file. We filter specifically for TCP port 502 (Modbus)
        capture = pyshark.FileCapture(file_path, display_filter="tcp.port == 502")
    except FileNotFoundError:
        print(f"[!] Error: Could not find {file_path}. Did you run simulator.py first?")
        return []

    anomalies = []
    
    # Tracking state for Replay Attacks
    # Maps Transaction ID to a list of timestamps
    transaction_history = defaultdict(list)

    print("[*] Parsing packets and applying heuristic rules...\n")
    
    for pkt in capture:
        try:
            # We only care about packets that have IP and Modbus layers
            if 'IP' not in pkt or 'MBTCP' not in pkt:
                continue
                
            timestamp = float(pkt.sniff_timestamp)
            src_ip = pkt.ip.src
            
            # Extract MBAP header fields
            trans_id = int(pkt.mbtcp.trans_id)
            
            # Extract Modbus PDU fields (if present)
            if hasattr(pkt, 'modbus') and hasattr(pkt.modbus, 'func_code'):
                func_code = int(pkt.modbus.func_code)
            else:
                # Sometimes pyshark maps it directly under mbtcp depending on the packet structure
                func_code = None 
                
            if func_code is None:
                continue

            # ==========================================
            # RULE 1: FUZZING DETECTION
            # ==========================================
            if func_code not in VALID_FUNCTION_CODES:
                anomalies.append({
                    "timestamp": f"{timestamp:.3f}",
                    "anomaly_type": "Fuzzing Attempt",
                    "source_ip": src_ip,
                    "evidence": f"Invalid/Reserved Modbus Function Code detected: 0x{func_code:02x}."
                })
                continue # Skip further checks for this malformed packet

            # ==========================================
            # RULE 2: COMMAND INJECTION DETECTION
            # ==========================================
            if func_code in WRITE_FUNCTION_CODES and src_ip != HMI_IP:
                anomalies.append({
                    "timestamp": f"{timestamp:.3f}",
                    "anomaly_type": "Command Injection",
                    "source_ip": src_ip,
                    "evidence": f"Unauthorized Write Command (Function Code 0x{func_code:02x}) detected from non-baseline IP."
                })

            # ==========================================
            # RULE 3: REPLAY ATTACK DETECTION
            # ==========================================
            # If we see the exact same Transaction ID from the HMI in less than 50ms, it's a replay.
            if src_ip == HMI_IP:
                history = transaction_history[trans_id]
                history.append(timestamp)
                
                # Check the last 5 packets with this ID
                if len(history) >= 5:
                    time_delta = history[-1] - history[-5]
                    # If 5 packets with the same ID arrived in under 50ms (0.05s)
                    if time_delta < 0.05:
                        # Prevent duplicate alerts for the same burst
                        if not any(a['anomaly_type'] == 'Replay Attack' and a['evidence'].endswith(f"ID: {trans_id})") for a in anomalies):
                            anomalies.append({
                                "timestamp": f"{history[-5]:.3f} - {history[-1]:.3f}",
                                "anomaly_type": "Replay Attack",
                                "source_ip": src_ip,
                                "evidence": f"Detected burst of identical packets (Transaction ID: {trans_id}) within {time_delta*1000:.0f}ms, violating the polling baseline."
                            })

        except AttributeError:
            # Safely ignore packets that are malformed or missing expected layer attributes
            continue

    capture.close()
    return anomalies

def generate_report(anomalies):
    if not anomalies:
        print("[+] No anomalies detected. Traffic matches baseline.")
        return

    print("==================================================")
    print("      ICS EXPLAINABILITY REPORT GENERATED         ")
    print("==================================================")
    
    # Output as pretty-printed JSON for the judges
    report_json = json.dumps(anomalies, indent=2)
    print(report_json)
    
    # Save to a file
    with open("anomaly_report.json", "w") as f:
        f.write(report_json)
    print("\n[*] Report saved to 'anomaly_report.json'.")



# ... (keep all your existing functions)

if __name__ == "__main__":
    # Fix for "RuntimeError: There is no current event loop"
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    # Now run your analysis
    detected_anomalies = analyze_pcap(PCAP_FILE)
    generate_report(detected_anomalies)