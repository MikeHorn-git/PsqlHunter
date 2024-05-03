import argparse
import pyshark
import re
from urllib.parse import unquote
from tqdm import tqdm

def extract_sqli(pcap):
    cap = pyshark.FileCapture(pcap)

    sql_pattern = re.compile(
        r'\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|GRANT|REVOKE|EXEC|LOAD_FILE|OUTFILE|UNION)\b|\b(AND|OR)\b\s*[\s=!<>]|--|\b(SLEEP|WAITFOR|BENCHMARK)\b\(\s*',
    )

    results = []

    for packet in tqdm(cap, desc="Processing packets"):
        if hasattr(packet, 'http') and hasattr(packet.http, 'request_uri'):
            url = unquote(packet.http.request_uri)
            if sql_pattern.search(url):
                timestamp = packet.sniff_time.strftime("%Y-%m-%d %H:%M:%S")
                results.append(f"Packet {packet.number}: Timestamp: {timestamp}, URL: {url}")

    for result in results:
        print(result)

def main():
    parser = argparse.ArgumentParser(description='Hunt sql command in pcap.')
    parser.add_argument('pcap', help='Path to the pcap file')
    args = parser.parse_args()

    extract_sqli(args.pcap)

if __name__ == "__main__":
    main()
