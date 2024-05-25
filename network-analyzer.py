import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw, Ether
import signal
import sys

packet_counts = {
    'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'DNS': 0, 'HTTP': 0,
    'SSL/TLS': 0, 'SMTP': 0, 'FTP': 0, 'SNMP': 0, 'SSH':0 ,'RDP':0, 'Other': 0
}

packets_data = []

def process_ssh(packet):
    if TCP in packet and (packet[TCP].dport == 22 or packet[TCP].sport == 22):
        packet_counts['SSH'] += 1
        return "SSH traffic detected"
    return ""

def process_rdp(packet):
    if TCP in packet and (packet[TCP].dport == 3389 or packet[TCP].sport == 3389):
        packet_counts['RDP'] += 1
        return "RDP traffic detected"
    return ""

def process_dns(packet):
    if DNS in packet and (packet[DNS].qd is not None):
        packet_counts['DNS'] += 1
        return f"DNS query: {packet[DNS].qd.qname.decode()}"
    return ""

def process_http(packet):
    if TCP in packet and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
        if Raw in packet:
            packet_counts['HTTP'] += 1
            try:
                return f"HTTP data: {packet[Raw].load.decode()[:50]}..."
            except UnicodeDecodeError:
                return "HTTP data: [non-ASCII data]"
    return ""

def process_ssl_tls(packet):
    if TCP in packet and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
        packet_counts['SSL/TLS'] += 1
        return "Possible SSL/TLS traffic"
    return ""

def process_smtp(packet):
    if TCP in packet and (packet[TCP].dport == 25 or packet[TCP].sport == 25):
        packet_counts['SMTP'] += 1
        return "SMTP traffic detected"
    return ""

def process_ftp(packet):
    if TCP in packet and (packet[TCP].dport in [20, 21] or packet[TCP].sport in [20, 21]):
        packet_counts['FTP'] += 1
        return "FTP traffic detected"
    return ""

def process_snmp(packet):
    if UDP in packet and (packet[UDP].dport == 161 or packet[UDP].sport == 161):
        packet_counts['SNMP'] += 1
        return "SNMP traffic detected"
    return ""

def handle_packet(packet):
    global packet_counts, packets_data
    
    protocol = 'Other'
    detail = ""

    if Ether in packet:
        if ARP in packet:
            protocol = 'ARP'
        elif IP in packet:
            if TCP in packet:
                protocol = 'TCP'
                detail = (process_http(packet) or process_ssl_tls(packet) or
                          process_smtp(packet) or process_ftp(packet) or
                          process_ssh(packet) or process_rdp(packet))
            elif UDP in packet:
                protocol = 'UDP'
                detail = (process_dns(packet) or process_snmp(packet))
            elif ICMP in packet:
                protocol = 'ICMP'
        packet_counts[protocol] += 1

    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
    else:
        ip_src = "None"
        ip_dst = "None"

    sport = packet.sport if protocol in ['TCP', 'UDP'] else "-"
    dport = packet.dport if protocol in ['TCP', 'UDP'] else "-"

    packets_data.append({
        'protocol': protocol,
        'source_ip': ip_src,
        'source_port': sport,
        'destination_ip': ip_dst,
        'destination_port': dport,
        'details': detail
    })

    print(f"{protocol} packet from {ip_src}:{sport} to {ip_dst}:{dport} | {detail}")

def save_data():
    df = pd.DataFrame(packets_data)
    df.to_csv('network_traffic.csv', index=False)
    print("Data saved to network_traffic.csv")

def signal_handler(sig, frame):
    print('Interrupt received, stopping packet capture and saving data...')
    save_data()
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    print("Starting packet capture. Press Ctrl+C to stop and save data.")
    sniff(prn=handle_packet, store=False)

if __name__ == "__main__":
    main()
