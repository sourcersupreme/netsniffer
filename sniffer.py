from scapy.all import sniff, IP, TCP, Raw
from collections import defaultdict
import time

# Trackers
packet_count = defaultdict(int)
port_scan = defaultdict(set)
start_time = time.time()

# Trusted IPs (avoid false positives)
trusted_ips = [
    "140.82.114.22",  # GitHub (example)
]

def process_packet(packet):
    global start_time

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        # Ignore trusted IPs
        if src in trusted_ips:
            return

        print(f"\n[+] {src} -> {dst}")

        # -------------------------
        # 🚨 DoS Detection (Rate-based)
        # -------------------------
        packet_count[src] += 1
        current_time = time.time()
        elapsed = current_time - start_time

        if elapsed > 0:
            rate = packet_count[src] / elapsed
            if rate > 100:
                print(f"[ALERT] Possible DoS from {src} ({rate:.2f} pkt/sec)")

        # -------------------------
        # 🚨 Port Scan Detection
        # -------------------------
        if packet.haslayer(TCP):
            dport = packet[TCP].dport
            port_scan[src].add(dport)

            if len(port_scan[src]) > 50:
                print(f"[ALERT] Possible Port Scan from {src}")

    # -------------------------
    # 🚨 Suspicious Payload Detection
    # -------------------------
    if packet.haslayer(Raw):
        try:
            data = packet[Raw].load.decode(errors="ignore").lower()

            keywords = ["username", "password", "login", "admin"]

            for word in keywords:
                if word in data:
                    print(f"[ALERT] Suspicious Data: {data}")
                    break
        except:
            pass

    # -------------------------
    # 🔄 Reset counters every 10 seconds
    # -------------------------
    if time.time() - start_time > 10:
        packet_count.clear()
        port_scan.clear()
        start_time = time.time()


print("🚨 IDS Sniffer Started...\n")
sniff(prn=process_packet, store=False)
