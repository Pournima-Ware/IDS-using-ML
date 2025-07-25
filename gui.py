import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
from scapy.all import sniff
import re
from datetime import datetime

# Signatures to match
signatures = [
    b"SELECT.*FROM",
    b"<script>.*</script>",
    b"Nmap",
    b"' OR '1'='1",
]

# GUI App
class IDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Python IDS Dashboard")
        self.root.geometry("700x400")
        self.sniffing = False

        self.start_button = tk.Button(root, text="Start IDS", command=self.start_sniffer, bg="green", fg="white")
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(root, text="Stop IDS", command=self.stop_sniffer, bg="red", fg="white")
        self.stop_button.pack(pady=5)

        self.alert_text = scrolledtext.ScrolledText(root, width=85, height=20)
        self.alert_text.pack(padx=10, pady=10)
        self.alert_text.insert(tk.END, ">> IDS Dashboard Initialized...\n")

    def log_alert(self, payload):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = f"[{timestamp}] ALERT: Suspicious packet detected!\nPayload: {payload}\n\n"
        self.alert_text.insert(tk.END, alert_msg)
        self.alert_text.see(tk.END)

        with open("logs/alerts.log", "a") as log_file:
            log_file.write(alert_msg)

    def process_packet(self, packet):
        if packet.haslayer("Raw"):
            payload = bytes(packet["Raw"].load)
            for signature in signatures:
                if re.search(signature, payload, re.IGNORECASE):
                    self.log_alert(payload)
                    break

    def sniffer_thread(self):
        sniff(filter="ip", prn=self.process_packet, store=False, stop_filter=lambda x: not self.sniffing)

    def start_sniffer(self):
        if not self.sniffing:
            self.sniffing = True
            self.alert_text.insert(tk.END, ">> IDS Started...\n")
            Thread(target=self.sniffer_thread, daemon=True).start()

    def stop_sniffer(self):
        self.sniffing = False
        self.alert_text.insert(tk.END, ">> IDS Stopped.\n")


# Run GUI
if __name__ == "__main__":
    import os
    os.makedirs("logs", exist_ok=True)

    root = tk.Tk()
    app = IDSApp(root)
    root.mainloop()
