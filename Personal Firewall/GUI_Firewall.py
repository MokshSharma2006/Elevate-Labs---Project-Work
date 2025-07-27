import os
import sys
import time
import threading
from tkinter import *
from tkinter.scrolledtext import ScrolledText
from collections import defaultdict
from scapy.all import sniff, IP, TCP

THRESHOLD = 40

# Read IPs from file
def read_ip_file(filename):
    if not os.path.exists(filename):
        return set()
    with open(filename, "r") as file:
        return set(line.strip() for line in file)

# Check Nimda worm
def is_nimda_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = packet[TCP].payload
        return "GET /scripts/root.exe" in str(payload)
    return False

# Log events
def log_event(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] {message}"
    log_text.insert(END, full_message + "\n")
    log_text.see(END)
    with open("logs/network_log.txt", "a") as f:
        f.write(full_message + "\n")

def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    if src_ip in whitelist_ips:
        return

    if src_ip in blacklist_ips:
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_event(f"Blocked blacklisted IP: {src_ip}")
        blocked_ips.add(src_ip)
        update_blocked_list()
        return

    if is_nimda_worm(packet):
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_event(f"Blocked Nimda worm source: {src_ip}")
        blocked_ips.add(src_ip)
        update_blocked_list()
        return

    packet_count[src_ip] += 1
    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                log_event(f"Blocked IP: {ip}, Rate: {packet_rate:.2f} pkt/s")
                blocked_ips.add(ip)
                update_blocked_list()
        packet_count.clear()
        start_time[0] = current_time

# Start sniffing
def start_monitoring():
    global sniffing
    sniffing = True
    threading.Thread(target=sniff_packets, daemon=True).start()
    log_event("Started monitoring network traffic...")

def sniff_packets():
    sniff(filter="ip", prn=packet_callback, stop_filter=lambda x: not sniffing)

# Stop sniffing
def stop_monitoring():
    global sniffing
    sniffing = False
    log_event("Stopped monitoring network traffic...")

# Update blocked list in GUI
def update_blocked_list():
    blocked_listbox.delete(0, END)
    for ip in sorted(blocked_ips):
        blocked_listbox.insert(END, ip)

# GUI Setup
root = Tk()
root.title("Network Traffic Monitor")
root.geometry("700x500")

frame_top = Frame(root)
frame_top.pack(pady=10)

start_button = Button(frame_top, text="Start Monitoring", command=start_monitoring, bg="green", fg="white")
start_button.pack(side=LEFT, padx=10)

stop_button = Button(frame_top, text="Stop Monitoring", command=stop_monitoring, bg="red", fg="white")
stop_button.pack(side=LEFT, padx=10)

frame_middle = Frame(root)
frame_middle.pack(fill=BOTH, expand=True)

blocked_label = Label(frame_middle, text="Blocked IPs")
blocked_label.pack()

blocked_listbox = Listbox(frame_middle, height=10, width=40)
blocked_listbox.pack(pady=5)

log_label = Label(root, text="Event Logs")
log_label.pack()

log_text = ScrolledText(root, height=10, width=80)
log_text.pack(padx=10, pady=5)

# Initialize variables
if os.geteuid() != 0:
    print("This script requires root privileges.")
    sys.exit(1)

os.makedirs("logs", exist_ok=True)
whitelist_ips = read_ip_file("whitelist.txt")
blacklist_ips = read_ip_file("blacklist.txt")

packet_count = defaultdict(int)
start_time = [time.time()]
blocked_ips = set()
sniffing = False

# Launch GUI
root.mainloop()
