# PsqlHunter

# Screenshots
![image](https://github.com/MikeHorn-git/PsqlHunter/assets/123373126/491e7fb5-69df-4a07-a383-7f77f19e64f5)
-----
![image](https://github.com/MikeHorn-git/PsqlHunter/assets/123373126/174b650f-20cd-4c44-81b2-109ab9dc788c)


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
- [ ] Reduce possible false positive.
