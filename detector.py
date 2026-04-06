from collections import defaultdict
import time
from config import PORT_SCAN_THRESHOLD, TIME_WINDOW

scan_tracker = defaultdict(list)

def detect_port_scan(src_ip, dst_port):
    current_time = time.time()

    scan_tracker[src_ip].append((dst_port, current_time))

    # Remove old entries
    scan_tracker[src_ip] = [
        (port, t) for port, t in scan_tracker[src_ip]
        if current_time - t <= TIME_WINDOW
    ]

    unique_ports = set(port for port, _ in scan_tracker[src_ip])

    if len(unique_ports) > PORT_SCAN_THRESHOLD:
        return True

    return False
