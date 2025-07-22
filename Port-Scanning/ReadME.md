# ⚡ Advanced Python Port Scanner

A fast, multithreaded, and color-coded port scanner written in Python. This tool supports both single IP and subnet scanning, with customizable port ranges, designed for ethical hacking and network security assessments.

> 🛑 **Disclaimer:** This tool is intended for **educational** and **authorized** use only. Scanning networks without permission may be illegal.

---

## 🚀 Features

- ✅ Multithreaded for faster scanning
- 🌐 Supports scanning a single IP or a whole subnet (e.g., `192.168.1.0/24`)
- 🔢 Custom port range scanning (e.g., `-p 20-443`)
- 🎨 Color-coded output using `colorama`
- ⚙️ Command-line arguments for automation and flexibility

---

## 🧠 How It Works

- Uses `argparse` to parse user input for target IP/subnet and port range
- If a subnet is given (CIDR notation), it expands to all IPs in that range
- Creates threads for each port to scan quickly
- Checks if a port is open using `socket.connect_ex()`
- Prints results in green for open ports

---

## 📦 Requirements

- Python 3.x
- [`colorama`](https://pypi.org/project/colorama/)

### Install colorama (if not installed):

```bash
pip install -r requirements.txt

```
## ⚙️ Usage

### Basic Scan (default ports 1–1024):
 ```bash
python3 Port-Scanning.py -t 45.33.32.156
```
### Output - default port scan is from 1 to 1024

[+] Scanning 45.33.32.156 ...
[+] Open port 22 .
[+] Open port 80 .

### Custom Port Range:
``` bash
python3 Port-Scanner.py -t 45.33.32.156 -p 20-443
```
### Output 
scan the only selected port 
---

Scanning 45.33.32.156...
[+] Open Port 22 .
[+] Open Port 80 .

### Scan a Subnet:
```bash 
python3 Port-Scanner.py -t 45.33.32.156/24 -p 80-100
```
### Output 
scan the entire subnet 
--- 
Scanning 45.33.32.0...
Scanning 45.33.32.1...
Scanning 45.33.32.2...
Scanning 45.33.32.3...
Scanning 45.33.32.4...
Scanning 45.33.32.5...
[+] Open Port 80 .
Scanning 45.33.32.6...
Scanning 45.33.32.7...
Scanning 45.33.32.8...
Scanning 45.33.32.9...
[+] Open Port 80 .
Scanning 45.33.32.10...
[+] Open Port 80 .

## 🔒 Legal Disclaimer
This tool is created for educational purposes only. You are responsible for complying with all applicable laws. The author assumes no liability for any misuse or damage caused.

## 👨‍💻 Author
Your Name – Akala Gowtham Sai Kumar

## 📄 License
This project is licensed under the MIT License – see the LICENSE file for details.