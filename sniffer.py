from scapy.all import sniff, IP, TCP, Raw

def process_packet(packet):
    if packet.haslayer(IP):
        print(f"\n[+] {packet[IP].src} -> {packet[IP].dst}")

    if packet.haslayer(Raw):
        try:
            data = packet[Raw].load.decode()
            print("[+] Data:", data)
        except:
            pass

sniff(prn=process_packet, store=False)
