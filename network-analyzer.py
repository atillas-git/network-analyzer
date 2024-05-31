import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw, Ether
import signal
import sys
import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
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

def gui_handle_packet(packet):
    handle_packet(packet)  # Call the original handler
    update_gui()  # Update GUI elements

def update_gui():
    for protocol in packet_counts:
        if protocol in treeview_packet_counts.item(protocol)['values']:
            treeview_packet_counts.item(protocol, values=(protocol, packet_counts[protocol]))
    plot_packet_counts()

def plot_packet_counts():
    plt.clf()
    protocols = list(packet_counts.keys())
    values = list(packet_counts.values())
    plt.bar(protocols, values, color='skyblue')
    plt.xlabel('Protocol')
    plt.ylabel('Packets')
    plt.xticks(rotation=45)
    plt.tight_layout()
    canvas.draw()


root = tk.Tk()
root.title("Network Packet Analyzer")

capture_active = tk.IntVar(value=0)

def on_closing():
    if capture_active.get() == 1:  # Check if capture is active
        stop_capture()
    root.destroy()

frame = ttk.Frame(root)
frame.pack(padx=10, pady=10)


treeview_packet_counts = ttk.Treeview(frame, columns=('protocol', 'count'))
treeview_packet_counts.heading('#0', text='Protocol')
treeview_packet_counts.heading('count', text='Count')
treeview_packet_counts.pack()

for protocol in packet_counts:
    treeview_packet_counts.insert('', 'end', iid=protocol, text=protocol, values=(protocol, 0))

button_start = ttk.Button(frame, text="Start Capture", command=lambda: start_capture())
button_start.pack(side=tk.LEFT, padx=5, pady=5)

button_stop = ttk.Button(frame, text="Stop Capture", command=lambda: stop_capture())
button_stop.pack(side=tk.LEFT, padx=5, pady=5)

button_save = ttk.Button(frame, text="Save Data", command=lambda: save_data())
button_save.pack(side=tk.LEFT, padx=5, pady=5)

fig, ax = plt.subplots(figsize=(10, 4))
canvas = FigureCanvasTkAgg(fig, master=root)
canvas_widget = canvas.get_tk_widget()
canvas_widget.pack()

def start_capture():
    capture_active.set(1)
    print("Starting packet capture. Press Stop to end.")
    # Initiate a thread for sniffing
    thread = threading.Thread(target=lambda: sniff(prn=gui_handle_packet, store=False, stop_filter=lambda x: capture_active.get() == 0))
    thread.daemon = True  # Set the thread as a daemon so it closes when the main program exits
    thread.start()

def stop_capture():
    capture_active.set(0)
    print("Capture stopped.")

def save_data():
    df = pd.DataFrame(packets_data)
    df.to_csv('network_traffic.csv', index=False)
    print("Data saved to network_traffic.csv")

root.protocol("WM_DELETE_WINDOW", on_closing)

root.mainloop()
