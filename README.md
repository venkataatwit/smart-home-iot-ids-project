# Smart Home IoT Intrusion Detection System

## Overview
The Smart Home IoT Intrusion Detection System (IoT IDS) is a Python-based security tool that monitors network traffic from IoT devices and detects suspicious activity such as port scans, SYN flood attacks, and abnormal traffic spikes.

This project was developed for COMP 3510 – Internet of Things Security.

---

## Problem Statement
IoT devices often have limited security features and are frequently targeted by attackers due to:

- Weak or default passwords
- Outdated firmware
- Lack of regular updates
- Always-on network connectivity

The goal of this project is to improve smart home security by identifying malicious network behavior in real time.

---

## Features
- Real-time packet capture using Scapy
- Port scan detection
- SYN flood detection
- Traffic spike detection
- Alert logging to CSV files
- Modular and extensible architecture

---

## Technologies Used
- Python 3
- Scapy
- Pandas
- Matplotlib
- Pytest

---

## Project Structure

```text
iot-intrusion-detection-system/
├── data/
├── docs/
├── src/
├── tests/
├── README.md
├── requirements.txt
└── main.py
```

---
## Windows Requirements

- Python 3.10 or newer
- Npcap installed
- PowerShell or Command Prompt opened as Administrator

---

---
## Installation

Clone the repository:

```bash
[git clone https://github.com/anagvenkat33/iot-intrusion-detection-system.git
cd iot-intrusion-detection-system](https://github.com/venkataatwit/smart-home-iot-ids-project)
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Running the Project

Start the intrusion detection system:

```bash
python main.py
```

---

## Running Tests

```bash
pytest
```

---

## Example Alerts

```text
[ALERT] Possible Port Scan Detected
Source IP: 192.168.1.50

[ALERT] SYN Flood Suspected
Source IP: 192.168.1.75
```
---
## Detection Rules

| Detection | Default threshold | Time window |
|---|---:|---:|
| Port scan | 10 unique destination ports | 10 seconds |
| SYN flood | 50 SYN packets | 10 seconds |
| Traffic spike | 200 packets from one source | 10 seconds |

---
## Author
Anag Venkat

Course: COMP 3510 – Internet of Things Security
