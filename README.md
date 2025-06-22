# GhostEye

🔍 GhostEye – All-in-One OSINT Reconnaissance CLI Tool (Made for Kali Linux)
GhostEye is a powerful, modular, and interactive command-line tool designed to automate the footprinting and reconnaissance phase of ethical hacking and red teaming. Built specifically for Kali Linux, it combines the most effective OSINT tools and techniques into a single interface, allowing security researchers to gather intelligence efficiently.

⚙️ Features:
🕵️‍♂️ Google Dorking + GHDB Integration
🌐 Site Report + DNSDumping
👤 Searching across social media platform
📡 DNS Footprinting 
🌍 Network Tracing
🎯 Advanced Reconnaissance
📬 Email Footprinting 
🧠 Live terminal output, no clutter, no GUI


--------|| 🧑‍💻 Author: ||--------
Developed by Jit Surani (alias: Js) – Cybersecurity Enthusiast

### 🧠 Ideal For:
Bug bounty hunters, 
OSINT researchers, 
Penetration testers, 
Students learning ethical hacking, 
Anyone who wants a one-stop recon toolkit

### 📦 System Requirements

GhostEye runs best on **Kali Linux**. 
These are the package that will be required to run this tool, Install it accordingly.
```bash
sudo apt update && sudo apt install -y
```
```bash
sudo apt install traceroute \
```
```bash
sudo apt install dig \
```
```bash
sudo apt install dnsutils \
```
```bash
sudo apt install git \
```
```bash
sudo apt install pipx \
```
```bash
sudo apt install whois \
```
```bash
sudo apt install tor \
```
```bash
sudo apt install python3-venv \
```
```bash
sudo apt install python3-pip
```

### Python Requirements:
- requests
- beautifulsoup4
- python-whois
- ipwhois
- dnspython
- socks
- stem
- aiohttp
- certifi
- charset-normalizer
- idna
- urllib3
- python-socks
- python-dotenv

NOTE: This all packets will be installed using requirements.txt

### ----------------||| -- SETUP INSTRUCTION -- |||----------------

1) First we will create a virtual Environment to install all the necessary files
```bash
git clone https://github.com/JitSurani/GhostEye.git
cd GhostEye
```
```bash
python3 -m venv osint-venv
source osint-venv/bin/activate
```

2) Now, installing necessary files
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

3) Now, install the main file Ghost Eye
```bash
python3 ghosteye.py
```

4) Run the tool
```bash
./ghosteye.py
```


### 📁 Project Structure
- GhostEye/
- ├── ghosteye.py---------------# Main CLI script
- ├── requirements.txt----------# All Python dependencies
- ├── LICENSE-------------------# MIT License
- ├── README.md-----------------# This file 
- └── venv/---------------------# (excluded) virtual environment



### ⚠️ Legal Disclaimer
GhostEye is intended for educational purposes only.
Do not use this tool on targets or phone numbers without explicit legal permission.
The developer is not responsible for any misuse or illegal activity conducted with this tool.


###
🔐 Use it ethically. Hack responsibly.
Built with 💻 by js — Jit Surani
###
---
## 📜 License

GhostEye is licensed under the [MIT License](LICENSE).
This tool is intended strictly for educational, ethical hacking, and authorized security testing only.  
The developer does not take responsibility for any misuse of this software.



