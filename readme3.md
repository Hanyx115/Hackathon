# 🏭 ICS Anomaly Detector & Traffic Simulator

An offline industrial traffic analysis toolset designed to simulate and detect adversarial attacks within Modbus/TCP networks. 

Built for **Challenge 3 — Industrial Protocol Anomalies**, this project consists of a custom packet generator that crafts simulated SCADA network traffic, and a deterministic detection engine that classifies anomalies (Replay, Fuzzing, and Command Injection) while providing clear, human-readable explainability reports.

## 🚀 The Problem & Our Approach
Industrial Control Systems (ICS) and protocols like Modbus were historically designed without modern security controls (no encryption, no authentication). This makes them highly susceptible to packet manipulation. 

While black-box machine learning models can detect anomalies, they often lack **explainability**—a critical requirement for OT (Operational Technology) security engineers who need to understand *why* an alert fired. 

**Our Solution:** We built a transparent, rule-based heuristic engine. It parses `.pcap` files, extracts core Modbus features, and flags deviations from the baseline polling cycle, outputting a detailed report with specific supporting evidence for every alert.

## 🧠 Architecture 

The project is split into two core components:

### 1. The Traffic Simulator (`simulator.py`)
Since real-world attack PCAPs are scarce, we built a custom simulator using `scapy`. It generates a baseline of normal HMI-to-PLC polling (Read Holding Registers) and programmatically injects three distinct attacks:
* **Command Injection:** A sudden, unauthorized `Write Single Register` command from an unknown IP address.
* **Fuzzing:** Malformed packets containing reserved or invalid Modbus Function Codes (e.g., `0x5A`).
* **Replay Attack:** A rapid-fire burst of identical `Read` requests reusing old Transaction IDs and violating the standard polling time delta.

### 2. The Offline Detector (`detector.py`)
A parsing and analysis engine that ingests the generated `.pcap` file using `pyshark`. It evaluates every packet against our deterministic ruleset and generates an Anomaly Report.

#### Explainability Logic (How it detects attacks):
| Attack Type | Detection Rule (Explainability) |
| :--- | :--- |
| **Command Injection** | Flags `Write` function codes (`0x05`, `0x06`, `0x0F`, `0x10`) originating from non-HMI IP addresses. |
| **Fuzzing** | Flags packets where the Function Code falls outside the standard Modbus application protocol specification (e.g., > `0x2B`). |
| **Replay Attack** | Flags bursts of packets with identical Transaction IDs occurring within an abnormally short time window (< 50ms). |

---

## 🛠️ Tech Stack
* **Language:** Python 3.9+
* **Packet Generation:** `scapy`
* **Packet Parsing:** `pyshark` (Wireshark/tshark wrapper)

---

## 🚦 Quick Start Guide

### Prerequisites
1. Install Python 3.9+.
2. Install Wireshark (required for `pyshark` to function).
3. Install the Python dependencies:
   ```bash
   pip install scapy pyshark
