from scapy.all import sniff, IP, TCP, Raw
from collections import defaultdict
import time

packet_count = defaultdict(int)
port_scan = defaultdict(set)
start_time = time.time()

def process_packet(packet):
    global start_time

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        print(f"\n[+] {src} -> {dst}")

        # Count packets per IP (DoS detection)
        packet_count[src] += 1

        if packet_count[src] > 50:
            print(f"[ALERT] Possible DoS attack from {src}")

        # Detect port scanning
        if packet.haslayer(TCP):
            dport = packet[TCP].dport
            port_scan[src].add(dport)

            if len(port_scan[src]) > 20:
                print(f"[ALERT] Possible Port Scan from {src}")

    # Detect suspicious payload
    if packet.haslayer(Raw):
        try:
            data = packet[Raw].load.decode(errors="ignore").lower()

            keywords = ["username", "password", "login", "admin"]

            for word in keywords:
                if word in data:
                    print(f"[ALERT] Suspicious Data Found: {data}")
        except:
            pass

    # Reset counters every 10 seconds
    if time.time() - start_time > 10:
        packet_count.clear()
        port_scan.clear()
        start_time = time.time()

print("🚨 IDS Started...\n")
sniff(prn=process_packet, store=False)
