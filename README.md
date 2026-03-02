# 🛡 SentinelScan

> ⚔️ Static + Online File Threat Scanner for Linux

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)
![Status](https://img.shields.io/badge/Status-Active-success)

SentinelScan is a professional command-line tool designed for static malware triage and online reputation analysis.

It combines local detection techniques with multi-engine cloud intelligence to provide structured and readable threat verdicts directly in your terminal.

---

## 🚀 Features

- 🔐 Hash calculation (MD5 / SHA-256)
- 🧬 Real file type detection (libmagic)
- 🧩 YARA rule scanning
- 🪟 Windows PE metadata analysis (pefile)
- 🧠 Heuristic suspicious string detection
- 🌐 Online multi-engine reputation (VirusTotal / OPSWAT)
- 🎨 Rich terminal UI (color-coded severity, tables, progress bar)
- 📊 Clear verdicts: **SAFE / SUSPICIOUS / MALICIOUS**

---

## 🧠 How It Works

SentinelScan performs layered analysis:

1. Static inspection (hashing, magic detection)
2. YARA pattern matching
3. PE structure analysis (if applicable)
4. Heuristic suspicious indicators
5. Optional online multi-engine reputation lookup
6. Risk scoring and final verdict

This makes it ideal for SOC triage, malware analysis labs, and security research.

---

## 📦 Installation

### System Dependencies

#### Debian / Ubuntu
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv libmagic1
