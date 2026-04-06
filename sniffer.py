from scapy.all import sniff, IP, TCP, Raw

def process_packet(packet):
    if packet.haslayer(IP):
        print(f"\n[+] Packet: {packet[IP].src} -> {packet[IP].dst}")

    if packet.haslayer(TCP):
        print(f"[+] TCP Port: {packet[TCP].sport} -> {packet[TCP].dport}")

    if packet.haslayer(Raw):
        print(f"[+] Data: {packet[Raw].load}")

print("Sniffer Started...\n")
sniff(prn=process_packet, store=False)
