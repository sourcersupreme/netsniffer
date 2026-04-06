import json
from datetime import datetime

def log_alert(alert_data):
    log_entry = {
        "timestamp": str(datetime.now()),
        "src_ip": alert_data.get("src_ip"),
        "dst_ip": alert_data.get("dst_ip"),
        "type": alert_data.get("type"),
        "message": alert_data.get("message")
    }

    with open("alerts_log.json", "a") as f:
        f.write(json.dumps(log_entry) + "\n")
