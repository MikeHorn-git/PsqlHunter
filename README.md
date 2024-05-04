# PsqlHunter

# Screenshots
![image](https://github.com/MikeHorn-git/PsqlHunter/assets/123373126/c447da84-afa3-4381-bdb4-390360566806)


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
- [ ] Reduce possible false positive
