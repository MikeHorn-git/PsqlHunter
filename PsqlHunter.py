#!/usr/bin/env python3

"""
PsqlHunter: A tool to hunt SQL commands in pcap files.
"""

import argparse
import csv
import json
import os
import re
from urllib.parse import unquote
import pyshark
from tabulate import tabulate
from tqdm import tqdm

def process_pcap(pcap):
    """
    Process a pcap file or a directory containing pcap files.
    """
    if os.path.isfile(pcap):
        return {pcap: extract_sql(pcap)}
    if os.path.isdir(pcap):
        results_dict = {}
        for filename in os.listdir(pcap):
            if filename.endswith(".pcap") or filename.endswith(".pcapng"):
                results_dict.update({filename: extract_sql(os.path.join(pcap, filename))})
        return results_dict
    print("[-] Invalid input")
    return None

def extract_sql(pcap):
    """
    Extract SQL commands from a pcap file.
    """
    cap = pyshark.FileCapture(pcap)

    sql_pattern = re.compile(
        r'\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|GRANT|REVOKE|EXEC|'
        r'LOAD_FILE|OUTFILE|UNION)\b|\b(AND|OR)\b\s*[\s=!<>]|--|\b(SLEEP|WAITFOR|BENCHMARK)\b\(\s*',
    )

    results = []

    for packet in tqdm(cap, desc=f"[+] Processing {os.path.basename(pcap)}"):
        if hasattr(packet, 'http') and hasattr(packet.http, 'request_uri'):
            url = unquote(packet.http.request_uri)
            if sql_pattern.search(url):
                timestamp = packet.sniff_time.strftime("%Y-%m-%d %H:%M:%S")
                # Truncate the URL for better display in the table
                truncated_url = (url[:80] + '...') if len(url) > 80 else url
                results.append({"Packet": str(packet.number), "Timestamp": timestamp, "URL": truncated_url})

    return results

def main():
    """
    Main function to handle command-line arguments and execute the script.
    """
    parser = argparse.ArgumentParser(description='Hunt SQL commands in pcap.')
    parser.add_argument('pcap', help='Path to the pcap file or folder containing pcap files')
    parser.add_argument('--csv', help='Export results to CSV', action='store_true')
    parser.add_argument('--json', help='Export results to JSON', action='store_true')
    parser.add_argument('--output', help='Path to the output folder', default='.')
    args = parser.parse_args()

    results_dict = process_pcap(args.pcap)

    if results_dict is None:
        print("[-] Invalid input: No pcap files found")
    elif not results_dict:
        print("[-] No SQL commands detected")
    else:
        for pcap_file, results in results_dict.items():
            if args.csv:
                csv_file = os.path.join(args.output, f"{os.path.splitext(os.path.basename(pcap_file))[0]}.csv")
                with open(csv_file, 'w', newline='') as csvfile:
                    fieldnames = ["Packet", "Timestamp", "URL"]
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(results)
                print(f"[+] Results exported to CSV: {csv_file}")

            if args.json:
                json_file = os.path.join(args.output, f"{os.path.splitext(os.path.basename(pcap_file))[0]}.json")
                with open(json_file, 'w') as jsonfile:
                    json.dump(results, jsonfile, indent=4)
                print(f"[+] Results exported to JSON: {json_file}")

            if not args.csv and not args.json:
                print(tabulate(results, headers=["Packet", "Timestamp", "URL"], tablefmt="grid"))

if __name__ == "__main__":
    main()
