from scapy.all import sniff, IP, TCP
from detector import detect_port_scan
from logger import log_alert
from alerts import send_email_alert
from geoip import get_location

def process_packet(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport

            if detect_port_scan(src, dst_port):
                location = get_location(src)

                alert_msg = f"Port scan detected from {src} ({location})"

                print(f"[ALERT] {alert_msg}")

                log_alert({
                    "src_ip": src,
                    "dst_ip": dst,
                    "type": "Port Scan",
                    "message": alert_msg
                })

                send_email_alert(alert_msg)

def start_sniffer(interface):
    print(f"[INFO] Starting sniffer on {interface}")
    sniff(iface=interface, prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffer("eth0")
