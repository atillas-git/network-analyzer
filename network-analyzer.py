import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw, Ether
import sys
import tkinter as tk
from tkinter import ttk, scrolledtext, Menu
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading

packet_counts = {
    'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'DNS': 0, 'HTTP': 0,
    'SSL/TLS': 0, 'SMTP': 0, 'FTP': 0, 'SNMP': 0, 'SSH': 0, 'RDP': 0, 'Other': 0
}
packets_data = []

def process_protocol(packet, protocol, port_list, count_key, message):
    if protocol in packet and any(packet[protocol].dport == p or packet[protocol].sport == p for p in port_list):
        packet_counts[count_key] += 1
        return message
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
                detail = (process_protocol(packet, TCP, [80], 'HTTP', 'HTTP traffic') or
                          process_protocol(packet, TCP, [443], 'SSL/TLS', 'SSL/TLS traffic') or
                          process_protocol(packet, TCP, [25], 'SMTP', 'SMTP traffic') or
                          process_protocol(packet, TCP, [20, 21], 'FTP', 'FTP traffic') or
                          process_protocol(packet, TCP, [22], 'SSH', 'SSH traffic') or
                          process_protocol(packet, TCP, [3389], 'RDP', 'RDP traffic'))
            elif UDP in packet:
                protocol = 'UDP'
                detail = (process_protocol(packet, UDP, [53], 'DNS', 'DNS query') or
                          process_protocol(packet, UDP, [161], 'SNMP', 'SNMP traffic'))
            elif ICMP in packet:
                protocol = 'ICMP'
        packet_counts[protocol] += 1

    ip_src = packet[IP].src if IP in packet else "None"
    ip_dst = packet[IP].dst if IP in packet else "None"
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
    log_message(f"{protocol} packet from {ip_src}:{sport} to {ip_dst}:{dport} | {detail}")

def gui_handle_packet(packet):
    handle_packet(packet)
    update_graph()

def update_graph():
    ax.clear()
    protocols = list(packet_counts.keys())
    values = list(packet_counts.values())
    ax.bar(protocols, values, color='skyblue')
    ax.set_xlabel('Protocol')
    ax.set_ylabel('Packets')
    ax.set_xticks(range(len(protocols)), labels=protocols, rotation=45)
    canvas.draw()

def start_capture():
    capture_active.set(1)
    log_message("Starting packet capture...")
    thread = threading.Thread(target=lambda: sniff(prn=gui_handle_packet, store=False, stop_filter=lambda x: capture_active.get() == 0))
    thread.daemon = True
    thread.start()

def stop_capture():
    capture_active.set(0)
    log_message("Packet capture stopped.")

def save_data():
    df = pd.DataFrame(packets_data)
    df.to_csv('network_traffic.csv', index=False)
    log_message("Data saved to network_traffic.csv")

def log_message(message):
    log_console.insert(tk.END, message + '\n')
    log_console.see(tk.END)

def on_closing():
    if capture_active.get() == 1:
        stop_capture()
    root.destroy()

# GUI setup
root = tk.Tk()
root.title("Advanced Network Packet Analyzer")
root.geometry("1000x800")

capture_active = tk.IntVar(value=0)

# Create a notebook (tabbed interface)
notebook = ttk.Notebook(root)
notebook.pack(fill=tk.BOTH, expand=True)

# Tabs
home_tab = ttk.Frame(notebook)
graph_tab = ttk.Frame(notebook)
log_tab = ttk.Frame(notebook)
notebook.add(home_tab, text='Home')
notebook.add(graph_tab, text='Graphs')
notebook.add(log_tab, text='Logs')

# Home Tab Content
control_frame = ttk.Frame(home_tab)
control_frame.pack(fill=tk.X, padx=10, pady=5)
button_start = ttk.Button(control_frame, text="Start Capture", command=lambda: start_capture())
button_start.pack(side=tk.LEFT, padx=10)
button_stop = ttk.Button(control_frame, text="Stop Capture", command=lambda: stop_capture())
button_stop.pack(side=tk.LEFT, padx=10)
button_save = ttk.Button(control_frame, text="Save Data", command=lambda: save_data())
button_save.pack(side=tk.LEFT, padx=10)

# Graph Tab Content
fig, ax = plt.subplots(figsize=(12, 5))
canvas = FigureCanvasTkAgg(fig, master=graph_tab)
canvas_widget = canvas.get_tk_widget()
canvas_widget.pack(fill=tk.BOTH, expand=True)

# Log Tab Content
log_console = scrolledtext.ScrolledText(log_tab, height=12)
log_console.pack(fill=tk.BOTH, expand=True)

# Menubar
menubar = Menu(root)
root.config(menu=menubar)
file_menu = Menu(menubar, tearoff=0)
file_menu.add_command(label="Save", command=lambda: save_data())
file_menu.add_separator()
file_menu.add_command(label="Exit", command=root.quit)
menubar.add_cascade(label="File", menu=file_menu)
help_menu = Menu(menubar, tearoff=0)
help_menu.add_command(label="About")
menubar.add_cascade(label="Help", menu=help_menu)

# Status Bar
status = ttk.Label(root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
status.pack(side=tk.BOTTOM, fill=tk.X)

# Define other functions as before, but include updates to status bar and log
def log_message(message):
    log_console.insert(tk.END, message + '\n')
    log_console.see(tk.END)
    status.config(text=message)

# Rest of the application logic (packet handling, start_capture, stop_capture, save_data) remains unchanged

root.mainloop()
