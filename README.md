# Smart Home IoT Intrusion Detection System

A lightweight, modular Intrusion Detection System (IDS) for smart home IoT networks built with **Python** and **Scapy**. The system captures live network traffic, analyzes packets in real time using rule-based detection algorithms, and generates alerts for suspicious network activity such as **port scans**, **SYN flood attacks**, and **traffic spikes**.

This project demonstrates practical cybersecurity concepts including packet analysis, network monitoring, intrusion detection, software architecture, automated testing, and real-time alert logging.

---

## Features

- Real-time packet capture using Scapy
- Live monitoring of network traffic
- Rule-based intrusion detection
- Rolling time-window analysis
- Detects:
  - Port Scan attacks
  - SYN Flood attacks
  - Traffic Spike anomalies
- CSV alert logging
- Modular project architecture
- Automated testing with Pytest
- Type hints and clean code organization
- MIT Licensed

---

# System Architecture

![Architecture](docs/architecture.png)

---

# Project Structure

```text
smart-home-iot-ids-project/
│
├── data/
│   ├── alerts.csv
│   └── sample_traffic.pcap
│
├── docs/
│   └── architecture.png
│
├── src/
│   ├── __init__.py
│   ├── alerts.py
│   ├── capture.py
│   └── detector.py
│
├── tests/
│   ├── __init__.py
│   ├── sample_packets.py
│   ├── test_alerts.py
│   ├── test_packet_parser.py
│   ├── test_port_scan.py
│   ├── test_syn_flood.py
│   └── test_traffic_spike.py
│
├── .github/
│   └── workflows/
│       └── tests.yml
│
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
└── main.py
```

---

# Detection Rules

## 1. Port Scan Detection

The detector monitors the number of **unique destination TCP ports** contacted by each source IP within a rolling time window.

An alert is generated when the configured threshold is exceeded.

Default configuration:

- 10 unique destination ports
- 10-second rolling window

---

## 2. SYN Flood Detection

The IDS monitors TCP SYN packets that initiate new connections.

If one host sends an unusually large number of SYN packets within the configured time window, a HIGH severity alert is generated.

Default configuration:

- 50 SYN packets
- 10-second rolling window

---

## 3. Traffic Spike Detection

The detector monitors packet volume from each source IP.

A MEDIUM severity alert is generated whenever a host exceeds the configured packet threshold within the rolling time window.

Default configuration:

- 200 packets
- 10-second rolling window
- 60-second alert cooldown

Traffic spike detection can help identify:

- abnormal device behavior
- compromised IoT devices
- denial-of-service activity
- network anomalies

---

# Detection Workflow

```text
          Live Network Interface
                    │
                    ▼
          Packet Capture (Scapy)
                    │
                    ▼
             Packet Parsing
                    │
                    ▼
          Intrusion Detection Engine
                    │
      ┌─────────────┼─────────────┐
      ▼             ▼             ▼
 Port Scan      SYN Flood    Traffic Spike
 Detection      Detection      Detection
      │             │             │
      └─────────────┼─────────────┘
                    ▼
             Alert Generation
                    │
                    ▼
          CSV Alert Logging
```

---

# Technologies Used

- Python 3.10+
- Scapy
- Pytest
- CSV
- Dataclasses
- Typing
- Git
- GitHub

---

# Installation

Clone the repository:

```bash
git clone https://github.com/venkataatwit/smart-home-iot-ids-project.git
cd smart-home-iot-ids-project
```

Create a virtual environment (recommended).

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### macOS / Linux

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# Requirements

- Python 3.10 or newer

Dependencies:

- Scapy
- Pytest

---

# Running the IDS

Administrator or root privileges are generally required because Scapy captures raw network packets.

Run:

```bash
python main.py
```

Example output:

```text
Starting Smart Home IoT IDS...

Monitoring live network traffic...

[HIGH] Port Scan | 192.168.1.20 -> 192.168.1.1 | Source contacted 10 unique TCP ports within 10 seconds.

[HIGH] SYN Flood | 192.168.1.35 -> 192.168.1.1 | Source sent 50 TCP SYN packets within 10 seconds.

[MEDIUM] Traffic Spike | 192.168.1.18 -> 192.168.1.1 | Source transmitted over 200 packets within 10 seconds.
```

Press **Ctrl + C** to stop monitoring.

---

# Alert Logging

Alerts are automatically written to:

```text
data/alerts.csv
```

Example:

| Timestamp | Alert Type | Source IP | Destination IP | Severity | Description |
|------------|------------|-----------|----------------|----------|-------------|
| 2026-07-19T18:22:01 | Port Scan | 192.168.1.20 | 192.168.1.1 | HIGH | Source contacted 10 unique TCP ports within 10 seconds. |
| 2026-07-19T18:24:15 | SYN Flood | 192.168.1.35 | 192.168.1.1 | HIGH | Source sent 50 TCP SYN packets within 10 seconds. |
| 2026-07-19T18:30:42 | Traffic Spike | 192.168.1.18 | 192.168.1.1 | MEDIUM | Source transmitted over 200 packets within 10 seconds. |

Alert history is preserved between program executions.

---

# Running Tests

Run all automated tests:

```bash
pytest
```

or

```bash
python -m pytest
```

Current test coverage includes:

- Packet parsing
- Port scan detection
- SYN flood detection
- Traffic spike detection
- CSV alert logging
- Alert file initialization

---

# Configuration

Detection thresholds are configured when the `IntrusionDetector` is created in `main.py`.

Default values are also defined in `src/detector.py`.

Current defaults:

```python
port_scan_threshold = 10
syn_flood_threshold = 50
traffic_spike_threshold = 200
window_seconds = 10
```

These values can be adjusted to better suit different network environments.

---

# Current Limitations

This project is intended as an educational intrusion detection system and is **not** a production security appliance.

Current limitations include:

- Rule-based detection only
- IPv4 traffic only
- No payload inspection
- No encrypted traffic analysis
- No machine learning models
- Thresholds require manual tuning
- Alerts stored locally as CSV
- No web dashboard
- No remote alert notifications

---

# Future Improvements

Potential enhancements include:

- Machine learning anomaly detection
- Flask or FastAPI dashboard
- Email notifications
- Discord or Slack alerts
- Docker deployment
- YAML configuration file
- SQLite or PostgreSQL alert storage
- IPv6 support
- Additional attack signatures
- PCAP replay mode
- Prometheus metrics
- Grafana dashboards
- Historical alert analytics
- Multi-threaded packet processing

---

# Educational Objectives

This project demonstrates practical experience with:

- Network packet analysis
- Intrusion detection systems
- Cybersecurity fundamentals
- Real-time packet capture
- Python software engineering
- Modular application design
- Automated testing
- CSV data persistence
- Network traffic analytics

---

# License

This project is licensed under the MIT License.

See the `LICENSE` file for details.

---

# Author

**Anag Venkat**

Bachelor of Science in Computer Science  
Wentworth Institute of Technology

GitHub

https://github.com/venkataatwit

Project Repository

https://github.com/venkataatwit/smart-home-iot-ids-project

---
