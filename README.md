# Goal
Aim to make sqli injection detection on pcap quicker for forensics analyst.

# Screenshot
![image](https://github.com/MikeHorn-git/PsqlHunter/assets/123373126/feb9e3fe-dad1-4d23-af19-e74285fbae1e)

# Requirement
* Tshark

# Installation
```bash
git clone https://github.com/MikeHorn-git/PsqlHunter.git
cd PsqlHunter/
pip install -r requirements.txt
```

# Usage
```bash
usage: PsqlHunter.py [-h] [--csv] [--json] [--output OUTPUT] pcap

Hunt sql commands in pcap.

positional arguments:
  pcap             Path to the pcap file or folder containing pcap files

options:
  -h, --help       show this help message and exit
  --csv            Export results to CSV
  --json           Export results to JSON
  --output OUTPUT  Path to the output folder
```

# To-Do
- [ ] Reduce possible false positives
