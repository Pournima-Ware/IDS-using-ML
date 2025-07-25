import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

# Simulate normal packet data for training
def generate_training_data():
    data = {
        'length': [60, 64, 70, 65, 80, 62, 66, 60, 67],
        'src_port': [443, 80, 443, 80, 22, 53, 80, 443, 22],
        'dst_port': [1025, 3456, 2345, 5678, 8765, 4567, 6789, 1234, 9876],
        'protocol': [6, 6, 6, 6, 6, 17, 6, 6, 6]  # 6 = TCP, 17 = UDP
    }
    df = pd.DataFrame(data)
    return df

# Train Isolation Forest
def train_model():
    df = generate_training_data()
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(df)
    joblib.dump(model, 'ml_model/ids_model.pkl')
    print("✅ ML model trained and saved.")

if __name__ == "__main__":
    train_model()
