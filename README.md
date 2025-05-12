# WMI-Whisper: Lightweight Post-Exploitation Framework (WMI + PowerShell + SMB)

A clean, minimal remote access toolkit leveraging native Windows features — WMI for code execution and authenticated SMB for output retrieval. Built for red teamers, researchers, and students.

> 🛡️ No dropped binaries, no `cmd.exe`, no noisy services — just pure tradecraft.

---

## ✨ Features
- ✔️ Executes commands remotely via `Win32_Process.Create`
- ✔️ Uses `powershell.exe -WindowStyle Hidden` 
- ✔️ Captures output via authenticated SMB share
- ✔️ Launches its own internal SMB server
- ✔️ No third-party payloads or shellcode
- ✔️ Compatible with modern Windows (10/11)

---

## 🧰 Requirements

- Python 3.8+
- Impacket (install from source or `pip`)
- Outbound SMB access (port 445) to your C2 box
- Valid credentials on the target system

---

## ⚙️ Setup

```bash
# Install system deps
sudo apt install python3 python3-pip -y

# Clone & install impacket
git clone https://github.com/fortra/impacket
cd impacket
pip install .
```

---
