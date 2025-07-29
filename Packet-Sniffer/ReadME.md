# 🔍 Packet Sniffer & MAC Filter Tool (Scapy-Based)

A lightweight CLI tool to sniff network packets and flag untrusted MAC addresses and possible ARP spoofing attempts using **Scapy**.

---

## 🚀 Features

- Captures live network traffic
- Logs IP, Protocol, and Port info
- Flags untrusted MAC addresses
- Detects potential ARP spoofing
- Saves logs to `logs/packet_log.txt`

---

## ⚙️ Setup

```bash
git clone https://github.com/agsk2601/Ethical-Hacking-Projects/Packet-Sniffer.git
cd Packet-Sniffer
./setup.sh
```
## Usage
``` bash
sudo python3 sniffer.py -i en0
```
## Output Example 
[IP] 192.168.1.10 -> 8.8.8.8 Proto: 6 [TCP] Port: 56789 -> 443
[!] packet from untrusted MAC: 5c:35:fc:58:34:40
[!] Possible ARP spoofing from 192.168.1.10 [5c:35:fc:58:34:40]

## Requirements
Python 3.8+
scapy
colorama

## Todo
Add DNS sniffer mode
Auto-detect interface

## Author
Akala Gowtham Sai Kumar