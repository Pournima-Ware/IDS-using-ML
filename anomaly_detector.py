from scapy.all import sniff
import joblib
import pandas as pd

model = joblib.load('ml_model/ids_model.pkl')

def extract_features(packet):
    try:
        length = len(packet)
        src_port = packet.sport if hasattr(packet, 'sport') else 0
        dst_port = packet.dport if hasattr(packet, 'dport') else 0
        proto = packet.proto if hasattr(packet, 'proto') else 0

        return pd.DataFrame([[length, src_port, dst_port, proto]], 
                            columns=['length', 'src_port', 'dst_port', 'protocol'])
    except:
        return None

def process_packet(packet):
    features = extract_features(packet)
    if features is not None:
        prediction = model.predict(features)[0]
        if prediction == -1:
            print("\n🚨 [ANOMALY DETECTED] Possible intrusion:")
            print("Packet Info:", packet.summary())

print("🤖 ML-Based IDS is running... Press CTRL+C to stop.")
sniff(filter="ip", prn=process_packet, store=False)
