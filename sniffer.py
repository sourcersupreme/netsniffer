from scapy.all import sniff, IP, TCP
import argparse

from detector import detect_port_scan
from logger import log_alert
from alerts import send_email_alert


# 🔹 Packet processing function
def process_packet(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport

            # 🔍 Detect Port Scan
            if detect_port_scan(src, dst_port):
                alert_msg = f"Port scan detected from {src}"

                print(f"[ALERT] {alert_msg}")

                # 📝 Log alert
                log_alert({
                    "src_ip": src,
                    "dst_ip": dst,
                    "type": "Port Scan",
                    "message": alert_msg
                })

                # 📧 Send email
                send_email_alert(alert_msg)


# 🔹 Sniffer function
def start_sniffer(interface):
    print(f"[INFO] Starting sniffer on {interface}")
    sniff(iface=interface, prn=process_packet, store=False)


# 🔹 Main entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Sniffer with Detection")

    parser.add_argument(
        "--interface",
        default="eth0",
        help="Network interface (eth0, wlan0, etc.)"
    )

    args = parser.parse_args()

    start_sniffer(args.interface)
