import os
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import queue
import datetime
import socket
import psutil
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import cpu_count

try:
    import scapy.all as scapy
except ImportError:
    import subprocess
    import sys

    subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy"])
    import scapy.all as scapy

# Global flag to control packet sniffing
sniffing = False
file_index = 1

# Queue for thread-safe GUI updates
packet_queue = queue.Queue(maxsize=1000)  # Increase queue size for higher throughput

# Thread pool for handling packet processing
max_workers = min(32, cpu_count() + 4)  # Use a reasonable number of threads based on CPU cores
executor = ThreadPoolExecutor(max_workers=max_workers)

# List of known malicious IPs for demonstration purposes
malicious_ips = ["192.168.1.100", "10.0.0.5"]

# List of common domains to identify
common_domains = ["youtube.com", "google.com", "facebook.com", "twitter.com", "instagram.com"]

# Cache for DNS resolutions to improve performance
dns_cache = {}

# Public IP ranges (IPv4)
public_ip_ranges = [
    ("1.0.0.0", "126.255.255.255"),
    ("128.0.0.0", "191.255.255.255"),
    ("192.0.0.0", "223.255.255.255"),
]

# Function to check if an IP address is public
def is_public_ip(ip_address):
    ip_int = int.from_bytes(socket.inet_aton(ip_address), 'big')
    for start, end in public_ip_ranges:
        if int.from_bytes(socket.inet_aton(start), 'big') <= ip_int <= int.from_bytes(socket.inet_aton(end), 'big'):
            return True
    return False

# Function to resolve IP addresses back to domain names (only public IPs)
def resolve_ip_to_domain(ip_address):
    if not is_public_ip(ip_address):
        return "N/A"
    if ip_address in dns_cache:
        return dns_cache[ip_address]
    try:
        domain_name = socket.gethostbyaddr(ip_address)[0]
        dns_cache[ip_address] = domain_name
        return domain_name
    except (socket.herror, socket.gaierror):
        return "N/A"

# Function to find the process associated with a given IP (only public IPs)
def find_process_by_ip(ip_address):
    if not is_public_ip(ip_address):
        return "Unknown", "N/A", "N/A"
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr and conn.raddr.ip == ip_address:
            try:
                process = psutil.Process(conn.pid)
                return process.name(), process.pid, process.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    return "Unknown", "N/A", "N/A"

# Function to identify the device or network based on the IP address
def identify_device(ip_address):
    if is_public_ip(ip_address):
        try:
            device_name = socket.gethostbyaddr(ip_address)[0]
            return device_name
        except (socket.herror, socket.gaierror):
            return "Unknown Device"
    return "Unknown Device"

# Function to analyze packet (only public IPs)
def analyze_packet(packet):
    packet_info = {
        "src_mac": packet.src if packet.haslayer(scapy.Ether) else "N/A",
        "dst_mac": packet.dst if packet.haslayer(scapy.Ether) else "N/A",
        "source": "N/A",
        "destination": "N/A",
        "protocol": "N/A",
        "sport": "N/A",
        "dport": "N/A",
        "malicious": False,
        "domain": "N/A",
        "resolved_domain": "N/A",
        "app_name": "N/A",
        "app_pid": "N/A",
        "app_exe": "N/A",
        "dns_query": "N/A",
        "device": "Unknown Device"
    }

    # Check if the packet has an IP layer and if the IP is public
    if packet.haslayer(scapy.IP):
        packet_info["source"] = packet[scapy.IP].src
        packet_info["destination"] = packet[scapy.IP].dst
        packet_info["protocol"] = packet[scapy.IP].proto

        # Get source and destination ports if available (e.g., for TCP/UDP)
        if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
            packet_info["sport"] = packet.sport
            packet_info["dport"] = packet.dport

        packet_info["resolved_domain"] = resolve_ip_to_domain(packet[scapy.IP].dst)

        # Identify the device or network based on the source IP address
        packet_info["device"] = identify_device(packet[scapy.IP].src)

        # Get the application details based on the destination IP
        app_name, app_pid, app_exe = find_process_by_ip(packet[scapy.IP].dst)
        packet_info["app_name"] = app_name
        packet_info["app_pid"] = app_pid
        packet_info["app_exe"] = app_exe

        # Check for malicious IPs
        if packet_info["source"] in malicious_ips or packet_info["destination"] in malicious_ips:
            packet_info["malicious"] = True

    # Check for DNS queries
    if packet.haslayer(scapy.DNSQR):
        dns_query = packet[scapy.DNSQR].qname.decode() if packet[scapy.DNSQR].qname else "N/A"
        packet_info["dns_query"] = dns_query
        print(f"Captured DNS Query: {dns_query}")  # Debugging: Print captured DNS queries
        for domain in common_domains:
            if domain in dns_query:
                packet_info["domain"] = domain
                break

    return packet_info

# Function to determine if the packet is a broadcast or contains only MAC addresses
def is_broadcast_or_mac_only(packet_info):
    # Check if the packet only has MAC addresses and no other meaningful data
    if packet_info["source"] == "N/A" and packet_info["destination"] == "N/A" and packet_info["dns_query"] == "N/A":
        return True
    # Check if the packet is a broadcast
    if packet_info["dst_mac"] == "ff:ff:ff:ff:ff:ff":
        return True
    return False

# Function to display packet in GUI
def display_packet(packet):
    packet_info = analyze_packet(packet)

    # Filter out broadcast and MAC-only packets
    if is_broadcast_or_mac_only(packet_info):
        return

    display_text = ", ".join(
        [f"Source MAC: {packet_info['src_mac']}" if packet_info['src_mac'] != "N/A" else "",
         f"Destination MAC: {packet_info['dst_mac']}" if packet_info['dst_mac'] != "N/A" else "",
         f"Source IP: {packet_info['source']}",
         f"Destination IP: {packet_info['destination']}",
         f"Protocol: {packet_info['protocol']}" if packet_info['protocol'] != "N/A" else "",
         f"Source Port: {packet_info['sport']}" if packet_info['sport'] != "N/A" else "",
         f"Destination Port: {packet_info['dport']}" if packet_info['dport'] != "N/A" else "",
         f"DNS Query: {packet_info['dns_query']}" if packet_info['dns_query'] != "N/A" else "",
         f"Domain: {packet_info['domain']}" if packet_info['domain'] != "N/A" else "",
         f"Resolved Domain: {packet_info['resolved_domain']}" if packet_info['resolved_domain'] != "N/A" else "",
         f"Device: {packet_info['device']}" if packet_info['device'] != "Unknown Device" else "",
         " [MALICIOUS]" if packet_info["malicious"] else ""
         ]).replace(", ,", "").strip(", ")

    display_text += "\n"
    packet_queue.put(display_text)

# Function to start packet sniffing
def start_sniffing():
    global sniffing, file_index
    sniffing = True
    scrolled_text.insert(tk.END, "Starting packet sniffing...\n", "info")
    scrolled_text.see(tk.END)

    # Reset file index
    file_index = 1

    def sniff_packets():
        while sniffing:
            scapy.sniff(prn=lambda pkt: executor.submit(display_packet, pkt), store=False)

    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.start()
    root.after(100, process_queue)

# Function to stop packet sniffing
def stop_sniffing():
    global sniffing
    sniffing = False
    scrolled_text.insert(tk.END, "Stopping packet sniffing...\n", "info")
    scrolled_text.see(tk.END)

# Function to process queue and update GUI
def process_queue():
    while not packet_queue.empty():
        display_text = packet_queue.get()
        scrolled_text.insert(tk.END, display_text, "packet")
        scrolled_text.see(tk.END)
    if sniffing:
        root.after(100, process_queue)

# Function to clear packet data when generating a report
def clear_packet_data():
    scrolled_text.delete(1.0, tk.END)

# Function to generate structured report without "N/A" fields and excluding packets with only basic info
def generate_report():
    global file_index
    # Stop sniffing before generating the report
    stop_sniffing()

    report_text = "Packet Sniffing Report\n"
    report_text += "=" * 30 + "\n\n"
    report_text += f"Report Generated on: {datetime.datetime.now()}\n"
    report_text += "\nSniffing Details:\n"
    report_text += "-" * 20 + "\n"

    packets = scrolled_text.get(1.0, tk.END).strip().split('\n')
    packet_data = packets[2:]

    report_text += f"Total Packets Captured: {len(packet_data)}\n\n"
    report_text += "Packet Information:\n"
    report_text += "-" * 20 + "\n"

    meaningful_packet_count = 0

    for i, packet in enumerate(packet_data, start=1):
        if packet.strip():  # Ensure it's not an empty line
            if any(key in packet for key in ["Source IP:", "Destination IP:", "DNS Query:", "Source Port:", "Destination Port:", "Protocol"]):
                # Filter out packets with only MAC addresses and broadcast packets
                if "Source IP: N/A" in packet and "Destination IP: N/A" in packet:
                    continue
                if "Destination MAC: ff:ff:ff:ff:ff:ff" in packet:
                    continue

                meaningful_packet_count += 1
                packet_lines = packet.split(", ")
                filtered_packet_lines = [line for line in packet_lines if "N/A" not in line]
                filtered_packet = ", ".join(filtered_packet_lines)

                report_text += f"Packet {meaningful_packet_count}:\n{filtered_packet}\n\n"

    report_text += f"Total Meaningful Packets Captured: {meaningful_packet_count}\n\n"

    report_scrolled_text.delete(1.0, tk.END)
    report_scrolled_text.insert(tk.END, report_text, "report")

    desktop_path = "C:\\Users\\patri\\OneDrive\\Desktop"
    while os.path.exists(os.path.join(desktop_path, f'packet_report_{file_index}.txt')):
        file_index += 1
    report_file_path = os.path.join(desktop_path, f'packet_report_{file_index}.txt')
    with open(report_file_path, "w") as report_file:
        report_file.write(report_text)

    scrolled_text.insert(tk.END, f"Report generated and saved as '{report_file_path}'\n", "info")
    scrolled_text.see(tk.END)

    # Clear packet data after generating the report
    clear_packet_data()

# Initialize main window
root = tk.Tk()
root.title("Packet Sniffing and Network Traffic Analysis")
root.geometry("1200x600")

# Set up styles
style = ttk.Style()
style.theme_use('clam')

# Define colors for the "hacker-themed" appearance
bg_color = "#000000"  # Very black background
fg_color = "#00FF00"  # Green text
info_color = "#00FF00"  # Green text for info

style.configure('TFrame', background=bg_color)
style.configure('TLabel', background=bg_color, foreground=fg_color)
style.configure('TButton', background=bg_color, foreground=fg_color, borderwidth=1)
style.map('TButton', background=[('active', '#333333')], foreground=[('active', fg_color)])

root.configure(bg=bg_color)

# Add a frame for controls
control_frame = ttk.Frame(root)
control_frame.pack(side=tk.TOP, fill=tk.X)

# Add a frame for displaying results
display_frame = ttk.Frame(root)
display_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Add a scrolled text widget for showing packet data
scrolled_text = scrolledtext.ScrolledText(display_frame, wrap=tk.WORD, background=bg_color, foreground=fg_color,
                                          insertbackground=fg_color, font=("Consolas", 12))
scrolled_text.tag_configure("info", foreground=info_color)
scrolled_text.tag_configure("packet", foreground=fg_color)
scrolled_text.pack(fill=tk.BOTH, expand=True)

# Add a frame for displaying report
report_frame = ttk.Frame(root)
report_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

# Add a scrolled text widget for showing report
report_scrolled_text = scrolledtext.ScrolledText(report_frame, wrap=tk.WORD, background=bg_color, foreground=fg_color,
                                                 insertbackground=fg_color, font=("Consolas", 12))
report_scrolled_text.tag_configure("report", foreground=fg_color)
report_scrolled_text.pack(fill=tk.BOTH, expand=True)

# Add start, stop, and generate report buttons
start_button = ttk.Button(control_frame, text="Start Sniffing", command=start_sniffing)
stop_button = ttk.Button(control_frame, text="Stop Sniffing", command=stop_sniffing)
generate_report_button = ttk.Button(control_frame, text="Generate Report", command=generate_report)

start_button.pack(side=tk.LEFT, padx=5, pady=5)
stop_button.pack(side=tk.LEFT, padx=5, pady=5)
generate_report_button.pack(side=tk.LEFT, padx=5, pady=5)

# Run the GUI loop
root.mainloop()
