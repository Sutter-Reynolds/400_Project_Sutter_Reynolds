import pyshark
import sys
import requests
from collections import defaultdict, Counter

def getCompany(ip):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}?fields=org')
        data = response.json()
        return data.get('org', 'Unknown')
    except Exception:
        return 'Unknown'
    
def findRating(protocols):
    if 'TLS' in protocols or 'SSL' in protocols:
        return 'High'
    elif 'IPSEC' in protocols:
        return 'Medium'
    elif 'HTTP' in protocols:
        return 'Low'
    else:
        return 'None'

def calculateProtocol(pcap_path):
    capture = pyshark.FileCapture(pcap_path, only_summaries=False, keep_packets=False)
    data = defaultdict(lambda: Counter())
    
    for packet in capture:
        srcIP = None
        protocols = []

        if hasattr(packet, 'ip'):
            srcIP = packet.ip.src
        
        for layer in packet.layers:
            if hasattr(layer, '_layer_name'):
                protocols.append(layer._layer_name.upper())
        
        if srcIP and protocols:
            for protocol in set(protocols):
                data[srcIP][protocol] += 1

    IPPercentages = {}
    for ip, counts in data.items():
        total = sum(counts.values())
        percentages = {protocol: (count / total) * 100 for protocol, count in counts.items()}
        IPPercentages[ip] = {
            'company': getCompany(ip),
            'percentages': percentages,
            'encryption_rating': findRating(set(percentages.keys()))
        }

    return IPPercentages

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Command line requires 2 arguments only!")
        sys.exit(1)

    pcap_path = sys.argv[1]
    results = calculateProtocol(pcap_path)

    for ip, info in results.items():
        print(f"IP Address: {ip} - {info['company']} - Encryption Rating: {info['encryption_rating']}")
        for protocol, percentage in info['percentages'].items():
            print(f"  {protocol}: {percentage:.2f}%")
        print()