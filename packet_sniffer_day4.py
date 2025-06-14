from scapy.all import sniff, IP, TCP
from collections import defaultdict
from datetime import datetime
import csv

# Port scan detection data structure
connection_tracker = defaultdict(set)
alert_log_file = open("alert_log.txt", "w")

# CSV for full packet logs
csv_file = open("packet_log_day4.csv", "w", newline="")
csv_writer = csv.writer(csv_file)
csv_writer.writerow(["Time", "Protocol", "Source IP", "Source Port", "Dest IP", "Dest Port", "Packet Size"])

def process_packet(packet):
    if IP in packet and TCP in packet:
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        size = len(packet)

        # Log the full packet
        csv_writer.writerow([timestamp, "TCP", ip_layer.src, tcp_layer.sport, ip_layer.dst, tcp_layer.dport, size])
        print(f"[{timestamp}] TCP {ip_layer.src}:{tcp_layer.sport} → {ip_layer.dst}:{tcp_layer.dport} | {size} bytes")

        # Track unique ports accessed by each source IP
        connection_tracker[ip_layer.src].add(tcp_layer.dport)

        # Port scan detection
        if len(connection_tracker[ip_layer.src]) > 10:
            alert_msg = f"[ALERT] Port Scan Detected from {ip_layer.src} at {timestamp} (More than 10 ports)\n"
            print("🚨", alert_msg.strip())
            alert_log_file.write(alert_msg)
            # Reset to avoid repeated alerts
            connection_tracker[ip_layer.src] = set()

print("Sniffing TCP packets for intrusion detection (30 packets)...\n")
sniff(filter="tcp", prn=process_packet, count=30)

csv_file.close()
alert_log_file.close()
print("\n✅ Done! Logs saved to 'packet_log_day4.csv' and alerts to 'alert_log.txt'")
