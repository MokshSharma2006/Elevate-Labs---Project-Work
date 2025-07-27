# Elevate-Labs-Project-Work

# 🔐 Internship Projects – Python for Cybersecurity

This repository contains two cybersecurity-focused projects developed during my internship. Both tools are written in **Python** and are designed to enhance understanding of **network security** and **Linux system hardening** through practical implementations.

---

## 📌 Projects Included

### 1. 🛡️ Personal Firewall with GUI (Python + Scapy)

A lightweight personal firewall tool that monitors and filters incoming network traffic in real time using packet inspection.

#### ✅ Features:
- Real-time packet sniffing using **Scapy**
- Graphical interface built with **Tkinter**
- Detects:
  - High packet rate traffic (possible DoS attacks)
  - Signature-based threats like **Nimda worm**
- IP Whitelisting and Blacklisting
- Logs blocked IPs and events
- Uses **iptables** to block malicious traffic

#### 📁 File:
- `GUI_Firewall.py`

---

### 2. 🧰 Linux System Security Audit Tool

A command-line tool that performs comprehensive security checks on a Linux system and provides a structured audit report.

#### ✅ Features:
- User account audit (empty passwords, UID 0 check, aging policy)
- Critical file permissions check
- SSH configuration inspection
- Firewall status (UFW/iptables)
- Insecure service detection
- System update checker
- Kernel parameter validation
- Generates a **security score** and **JSON report**

#### 📁 File:
- `audit.py`

---

## 🔧 Requirements

- Python 3.x
- Root/sudo access (required for some operations)
- Linux-based OS
- Python modules:
- `scapy`, `tkinter`, `subprocess`, `os`, `json`, etc.

Install Scapy (if not already installed):

## bash
pip install scapy


---

## 🚀 How to Run

### Personal Firewall:

## bash
sudo python3 GUI_Firewall.py


### Linux Audit Tool:

## bash
sudo python3 audit.py


## 🙌 Acknowledgements

Special thanks to my mentors and internship organization for their support and guidance throughout the development of these tools.
