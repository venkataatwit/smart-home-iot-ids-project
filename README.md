# Smart Home IoT Intrusion Detection System

A lightweight, real-time Intrusion Detection System (IDS) for smart home IoT networks built with **Python** and **Scapy**. The system captures live network traffic, analyzes packets using rule-based detection algorithms, and generates alerts for suspicious activity such as **port scans**, **SYN flood attacks**, and **abnormal traffic spikes**.

This project demonstrates practical network security concepts, packet analysis, and real-time monitoring in a modular and extensible architecture suitable for academic research and cybersecurity portfolios.

---

## Features

- Live packet capture using Scapy
- Real-time network traffic monitoring
- Rule-based intrusion detection
- Detects:
  - Port Scan attacks
  - SYN Flood attacks
  - Traffic Spike anomalies
- Rolling time-window analysis
- CSV alert logging
- Modular architecture for easy extension
- Automated unit tests with Pytest
- Type hints and clean code organization

---

## Project Structure

```
smart-home-iot-ids-project/
│
├── main.py                 # Application entry point
├── requirements.txt
├── README.md
│
├── src/
│   ├── capture.py          # Packet capture
│   ├── detector.py         # Detection engine
│   ├── alerts.py           # Alert logging
│   └── __init__.py
│
├── tests/
│   ├── test_detector.py
│   ├── test_packet_parser.py
│   └── __init__.py
│
└── data/
    └── alerts.csv
```

---

## Detection Rules

### 1. Port Scan Detection

The detector tracks the number of unique destination ports contacted by each source IP within a rolling time window.

An alert is generated when the number of unique destination ports exceeds the configured threshold.

Default threshold:

- 10 unique destination ports
- 10-second rolling window

---

### 2. SYN Flood Detection

The IDS monitors TCP SYN packets that initiate new connections.

An alert is generated when a single source sends an unusually high number of SYN packets during the configured time window.

Default threshold:

- 50 SYN packets
- 10-second rolling window

---

### 3. Traffic Spike Detection

The detector monitors packet volume from each source IP.

If packet counts exceed the configured threshold within the rolling time window, a traffic spike alert is generated.

This helps identify:

- abnormal network behavior
- potential denial-of-service activity
- compromised IoT devices

---

## Detection Workflow

```
Live Network Interface
          │
          ▼
Packet Capture (Scapy)
          │
          ▼
Packet Parsing
          │
          ▼
Detection Engine
          │
 ┌────────┼────────┐
 ▼        ▼        ▼
Port   SYN Flood  Traffic
Scan              Spike
          │
          ▼
Alert Generation
          │
          ▼
CSV Logging
```

---

## Technologies Used

- Python 3.10+
- Scapy
- Pytest
- CSV
- Dataclasses
- Typing

---

## Installation

Clone the repository:

```bash
git clone https://github.com/venkataatwit/smart-home-iot-ids-project.git
cd smart-home-iot-ids-project
```

Create a virtual environment (recommended):

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

## Requirements

Python 3.10 or newer

Install dependencies:

```bash
pip install -r requirements.txt
```

Current dependencies include:

- Scapy
- Pytest

---

## Running the IDS

Administrator/root privileges are typically required because Scapy performs raw packet capture.

Run:

```bash
python main.py
```

Example output:

```
Starting Smart Home IoT IDS...

Monitoring live network traffic...

[HIGH] Port Scan detected from 192.168.1.15
[HIGH] SYN Flood detected from 192.168.1.20
[MEDIUM] Traffic Spike detected from 192.168.1.45
```

Stop monitoring with:

```
CTRL + C
```

---

## Alert Logging

Alerts are automatically written to:

```
data/alerts.csv
```

Example:

| Timestamp | Severity | Alert Type | Source IP | Details |
|------------|----------|------------|-----------|----------|
| 2026-07-16 13:42:05 | HIGH | Port Scan | 192.168.1.15 | 13 unique ports |
| 2026-07-16 13:43:17 | HIGH | SYN Flood | 192.168.1.20 | 57 SYN packets |
| 2026-07-16 13:44:51 | MEDIUM | Traffic Spike | 192.168.1.45 | 245 packets |

---

## Running Tests

Execute all tests:

```bash
pytest
```

or

```bash
python -m pytest
```

The test suite validates:

- Packet parsing
- Port scan detection
- SYN flood detection
- Traffic spike detection
- Detection logic behavior

---

## Configuration

The detection thresholds can be modified in `src/detector.py`.

Example:

```python
port_scan_threshold = 10
syn_flood_threshold = 50
traffic_spike_threshold = 200
window_seconds = 10
```

These values may be adjusted depending on the network environment to reduce false positives or increase detection sensitivity.

---

## Current Limitations

This project is intended as an educational IDS prototype and is not a production-ready intrusion detection system.

Current limitations include:

- Signature and rule-based detection only
- No machine learning or anomaly models
- IPv4 traffic only
- Does not inspect encrypted payloads
- Limited protocol awareness
- Thresholds require manual tuning
- Alerts are stored locally in CSV format
- No web dashboard or visualization interface

---

## Future Improvements

Potential future enhancements include:

- Machine learning anomaly detection
- Web dashboard for live monitoring
- Email or SMS alert notifications
- Support for IPv6
- Configuration file for detection thresholds
- Docker deployment
- REST API for alert retrieval
- Prometheus/Grafana integration
- Additional attack signatures
- Historical alert analytics
- Multi-threaded packet processing

---

## Educational Objectives

This project demonstrates practical experience with:

- Network packet analysis
- Cybersecurity monitoring
- Intrusion detection concepts
- Real-time packet capture
- Python software engineering
- Modular software architecture
- Automated testing
- Data logging
- Rule-based security analytics

---

## Author

**Anag Venkat**

Computer Science Student  
Wentworth Institute of Technology

GitHub:
https://github.com/venkataatwit

Project Repository:
https://github.com/venkataatwit/smart-home-iot-ids-project

---
