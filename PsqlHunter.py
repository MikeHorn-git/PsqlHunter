import argparse
import csv
import json
import os
import pyshark
import re
from tabulate import tabulate
from tqdm import tqdm
from urllib.parse import unquote

def process_pcap(pcap):
    if os.path.isfile(pcap):
        return extract_sql(pcap)
    elif os.path.isdir(pcap):
        results = []
        for filename in os.listdir(pcap):
            if filename.endswith(".pcap") or filename.endswith(".pcapng"):
                results.extend(extract_sql(os.path.join(pcap, filename)))
        return results
    else:
        print("[-] Invalid input")
        return None

def extract_sql(pcap):
    cap = pyshark.FileCapture(pcap)

    sql_pattern = re.compile(
        r'\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|GRANT|REVOKE|EXEC|LOAD_FILE|OUTFILE|UNION)\b|\b(AND|OR)\b\s*[\s=!<>]|--|\b(SLEEP|WAITFOR|BENCHMARK)\b\(\s*',
    )

    results = []

    for packet in tqdm(cap, desc=f"[+] Processing {os.path.basename(pcap)}"):
        if hasattr(packet, 'http') and hasattr(packet.http, 'request_uri'):
            url = unquote(packet.http.request_uri)
            if sql_pattern.search(url):
                timestamp = packet.sniff_time.strftime("%Y-%m-%d %H:%M:%S")
                # Truncate the URL for better display in the table
                truncated_url = (url[:80] + '...') if len(url) > 80 else url
                results.append(["Packet " + str(packet.number), timestamp, truncated_url])


    return results

def main():
    parser = argparse.ArgumentParser(description='Hunt sql commands in pcap.')
    parser.add_argument('pcap', help='Path to the pcap file or folder containing pcap files')
    parser.add_argument('--csv', help='Export results to CSV', action='store_true')
    parser.add_argument('--json', help='Export results to JSON', action='store_true')
    parser.add_argument('--output', help='Path to the output folder', default='.')
    args = parser.parse_args()

    results = process_pcap(args.pcap)
    
    if results:
        if args.csv:
            csv_file = os.path.join(args.output, "output.csv")
            with open(csv_file, 'w', newline='') as csvfile:
                fieldnames = ["Packet Number", "Timestamp", "URL"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
            print(f"[+] Results exported to CSV: {csv_file}")

        if args.json:
            json_file = os.path.join(args.output, "output.json")
            with open(json_file, 'w') as jsonfile:
                json.dump(results, jsonfile, indent=4)
            print(f"[+] Results exported to JSON: {json_file}")

        if not args.csv and not args.json:
            print(tabulate(results, headers="keys", tablefmt="grid"))
    else:
        print("[-] No results found")

if __name__ == "__main__":
    main()
