# 🛡️ Firewall Log Analyzer
**GLA University — Network Security Mini Project**

**Team:** Samriddhi Pandey · Sanskriti Govil · Priya Singh · Riya Tomar  
**Guide:** Samsher Khan

---

## 📁 Project Structure

```
firewall_project/
│
├── app.py                  ← Main Flask backend (Python)
├── requirements.txt        ← Python dependencies
├── README.md
│
├── templates/
│   └── index.html          ← HTML dashboard
│
├── static/
│   ├── css/
│   │   └── style.css       ← All styles
│   └── js/
│       └── app.js          ← Frontend logic, charts, API calls
│
└── logs/
    └── sample_logs.csv     ← Sample firewall log to test upload
```

---

## 🚀 APNE SYSTEM PE KAISE CHALAYEIN (How to Run)

### Step 1 — Python Install Karo
Python 3.8+ chahiye. Check karo:
```bash
python --version
```
Agar nahi hai: https://www.python.org/downloads/

---

### Step 2 — Project Folder Mein Jao
```bash
cd firewall_project
```

---

### Step 3 — Dependencies Install Karo
```bash
pip install -r requirements.txt
```

---

### Step 4 — App Chalao
```bash
python app.py
```

Terminal mein dikhega:
```
==================================================
  Firewall Log Analyzer — GLA University
  Open: http://127.0.0.1:5000
==================================================
```

---

### Step 5 — Browser Mein Kholo
```
http://127.0.0.1:5000
```

**Done! 🎉**

---

## 🧪 Testing — Sample Log Upload

1. `logs/sample_logs.csv` file taiyar hai
2. App mein **"DROP LOG FILE HERE"** pe click karo
3. `sample_logs.csv` select karo
4. **"ANALYZE FILE"** button dabaao
5. Dashboard automatically update ho jaayega!

Sample log mein ye attacks hain:
- **Port Scan** — IP `10.0.0.99` se (13 alag ports scan kiye)
- **Brute Force** — IP `45.33.32.156` se (baar baar SSH port 22 try)
- **ICMP Flood** — IP `91.108.56.130` se (11 ICMP packets)
- **Suspicious Port Access** — port 31337, 4444 etc.

---

## ✨ Features

| Feature | Description |
|---|---|
| Upload & Parse | UFW, iptables, CSV format support |
| Real-Time Dashboard | 5 live charts — timeline, protocols, IPs, ports |
| Threat Detection | Port scan, brute force, ICMP flood, suspicious ports |
| Smart Search | Filter by IP, action, protocol, port, keyword |
| Export CSV | Download filtered logs as spreadsheet |
| Export PDF | Professional security report (needs reportlab) |
| Sample Data | Auto-loads 600 sample events on startup |

---

## 📋 Supported Log Formats

### CSV Format
```
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,action,bytes,interface
2024-03-10 08:01:12,192.168.1.15,10.0.0.1,54321,80,TCP,ALLOW,1024,eth0
```

### UFW Format (Linux)
```
Mar 10 08:01:12 server [UFW BLOCK] SRC=45.33.32.156 DST=10.0.0.1 SPT=12345 DPT=22 PROTO=TCP
```

### Real Linux Logs Kaise Lein:
```bash
# UFW logs
sudo cat /var/log/ufw.log > my_logs.log

# iptables logs
sudo dmesg | grep -i iptables > my_logs.log
```

---

## 🛠️ Technologies Used

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask |
| Data Processing | pandas, collections |
| PDF Reports | ReportLab |
| Frontend | HTML5, CSS3, JavaScript |
| Charts | Chart.js 4 |
| Fonts | IBM Plex Mono, Bebas Neue |
| OS / Logs | Linux UFW / iptables |

---

## ⚠️ Troubleshooting

**Port already in use?**
```bash
python app.py  # Default port 5000
# Ya change karo:
# app.run(port=8080)
```

**reportlab install nahi hua?**
```bash
pip install reportlab --break-system-packages
```

**Charts nahi dikh rahe?**
Internet connection chahiye pehli baar (Google Fonts + Chart.js CDN).

---

*GLA University — Network Security Mini Project © 2024*
