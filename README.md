# Description

Make sqli injection detection on pcap quicker for forensics analyst.
Detect sql requests in a pcap and render in a more friendly output.

## Screenshot

![image](./.assets/screen.png)

## Requirement

- [Tshark](https://www.wireshark.org/docs/man-pages/tshark.html)

### Arch

```bash
sudo pacman -S wireshark-cli
```

# Installation

### Classic

```bash
git clone https://github.com/MikeHorn-git/PsqlHunter.git
cd PsqlHunter/
pip install -r requirements.txt
```

### Nix

```bash
git clone https://github.com/MikeHorn-git/PsqlHunter.git
cd PsqlHunter/
nix develop
```

## Usage

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
