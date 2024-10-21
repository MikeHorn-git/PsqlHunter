# Description

Make sqli injection detection on pcap quicker for forensics analyst.
Detect sql requests in a pcap and render in a more friendly output.

# Screenshot

![image](https://github.com/MikeHorn-git/PsqlHunter/assets/123373126/feb9e3fe-dad1-4d23-af19-e74285fbae1e)

# Requirement

* [Tshark](https://www.wireshark.org/docs/man-pages/tshark.html)

# Installation

```bash
git clone https://github.com/MikeHorn-git/PsqlHunter.git
cd PsqlHunter/
python3 -m venv .venv
source .venv/bin/activate
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
