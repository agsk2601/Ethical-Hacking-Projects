# 🔎 Subdomain Enumerator (Python)

A fast, multi-threaded subdomain enumeration tool written in Python. It uses DNS resolution and HTTP requests to find live subdomains and their status codes. Ideal for ethical hacking, bug bounty hunting, and cybersecurity students.

---

## ✨ Features

-  Accepts IP or domain targets
-  Uses a massive wordlist (auto-downloaded)
-  Multi-threaded for speed
-  HTTP response detection (200, 403, etc.)
-  Saves results to a clean output file
-  Optional Subfinder API integration

---

## 📦 Setup

### Step 1: Clone the repository
```bash
git clone https://github.com/yourusername/subdomain-enumerator.git
cd subdomain-enumerator
./setup.sh
```
### Step 2: Run the setup script
This will:
* Create a virtual environment
* Install dependencies
* Download a massive subdomain wordlist from SecLists

### Usage
Basic Scan:
``` bash
source .venv/bin/activate
python3 subdomain_enumerator.py -d example.com -w wordlists/subdomains.txt
```
### Output:
Results are saved to output/found.txt:
  [+] api.example.com ➜ 192.168.1.10 [HTTP 200]
  [+] login.example.com ➜ 192.168.1.11 [HTTP 403]

### Legal Notice
Use this tool only on domains you own or are authorized to test. Unauthorized scanning is illegal and unethical.

### To-Do
 * Export results as CSV/JSON
 * DNS record (CNAME/TXT) lookup
 * Recursive subdomain discovery
 * Screenshotting with headless browser

 ### Author
👨‍💻 Akala Gowtham Sai Kumar 
🏫 Cybersecurity Student @ UCM

### License
This project is open-source under the MIT License.
