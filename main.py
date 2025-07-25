from scapy.all import sniff
import re
from datetime import datetime

# Define common attack signatures (basic examples)
signatures = [
    b"SELECT.*FROM",           # SQL Injection
    b"<script>.*</script>",    # XSS
    b"Nmap",                   # Port scanning
    b"' OR '1'='1",            # SQL bypass
]

# Log alert
def log_alert(payload):
    with open("logs/alerts.log", "a") as log_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"[{timestamp}] ALERT: Suspicious packet detected!\nPayload: {payload}\n\n")

# Packet handler
def process_packet(packet):
    if packet.haslayer("Raw"):
        payload = bytes(packet["Raw"].load)
        for signature in signatures:
            if re.search(signature, payload, re.IGNORECASE):
                print("\n🚨 [ALERT] Suspicious packet detected!")
                print("Payload:", payload)
                log_alert(payload)
                break

# Start sniffing
def start_sniffer():
    print("🔍 IDS started... Monitoring traffic. Press CTRL+C to stop.")
    sniff(filter="ip", prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffer()
