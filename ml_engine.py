import numpy as np
import pickle
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime, timedelta

MODEL_PATH  = os.path.join(os.path.dirname(__file__), 'models', 'anomaly_model.pkl')
SCALER_PATH = os.path.join(os.path.dirname(__file__), 'models', 'scaler.pkl')

TRAINING_THRESHOLD = 30
ANOMALY_THRESHOLD  = -0.1


class BehaviorAnomalyDetector:
    def __init__(self):
        self.model          = None
        self.scaler         = StandardScaler()
        self.training_data  = []
        self.is_trained     = False
        self.total_sessions = 0
        self.anomaly_count  = 0
        self.load()

    def load(self):
        try:
            if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
                self.model      = pickle.load(open(MODEL_PATH,  'rb'))
                self.scaler     = pickle.load(open(SCALER_PATH, 'rb'))
                self.is_trained = True
                print("Model loaded from disk")
        except Exception as e:
            print(f"No saved model — starting fresh: {e}")

    def save(self):
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        pickle.dump(self.model,  open(MODEL_PATH,  'wb'))
        pickle.dump(self.scaler, open(SCALER_PATH, 'wb'))

    def add_training_sample(self, feature_vector):
        self.training_data.append(feature_vector)
        if len(self.training_data) >= TRAINING_THRESHOLD:
            self._train()

    def _train(self):
        X        = np.array(self.training_data)
        self.scaler  = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        self.model   = IsolationForest(
            n_estimators  = 200,
            contamination = 0.05,
            random_state  = 42,
            n_jobs        = -1,
        )
        self.model.fit(X_scaled)
        self.is_trained = True
        self.save()
        print(f"Model trained on {len(self.training_data)} sessions")

    def score(self, feature_vector):
        self.total_sessions += 1

        if not self.is_trained:
            self.add_training_sample(feature_vector)
            sessions_needed = TRAINING_THRESHOLD - len(self.training_data)
            return {
                'status'          : 'learning',
                'anomaly_score'   : None,
                'is_anomaly'      : False,
                'confidence'      : 0,
                'threat_level'    : 'LEARNING',
                'sessions_needed' : max(sessions_needed, 0),
                'message'         : f'Collecting baseline... {len(self.training_data)}/{TRAINING_THRESHOLD}',
            }

        X_scaled   = self.scaler.transform(feature_vector.reshape(1, -1))
        score      = float(self.model.score_samples(X_scaled)[0])
        pred       = self.model.predict(X_scaled)[0]
        is_anomaly = pred == -1 or score < ANOMALY_THRESHOLD

        if is_anomaly:
            self.anomaly_count += 1

        if score < -0.3:
            threat     = 'CRITICAL'
            confidence = min(abs(score) * 200, 99)
        elif score < -0.2:
            threat     = 'HIGH'
            confidence = min(abs(score) * 150, 90)
        elif score < -0.1:
            threat     = 'MEDIUM'
            confidence = min(abs(score) * 100, 75)
        elif score < 0:
            threat     = 'LOW'
            confidence = min(abs(score) * 80, 50)
        else:
            threat     = 'NORMAL'
            confidence = min(score * 100, 99)

        messages = {
            'CRITICAL': 'Highly anomalous — possible bot or attacker',
            'HIGH'    : 'Significant deviation from normal pattern',
            'MEDIUM'  : 'Unusual behavior detected — monitoring',
            'LOW'     : 'Slight deviation — within acceptable range',
            'NORMAL'  : 'Login behavior matches established baseline',
        }

        return {
            'status'        : 'active',
            'anomaly_score' : round(score, 4),
            'is_anomaly'    : bool(is_anomaly),
            'confidence'    : round(confidence, 1),
            'threat_level'  : threat,
            'total_sessions': self.total_sessions,
            'anomaly_count' : self.anomaly_count,
            'anomaly_rate'  : round(self.anomaly_count / self.total_sessions * 100, 1),
            'message'       : messages.get(threat, 'Unknown'),
        }

    def get_stats(self):
        return {
            'is_trained'      : self.is_trained,
            'training_samples': len(self.training_data),
            'total_sessions'  : self.total_sessions,
            'anomaly_count'   : self.anomaly_count,
            'anomaly_rate'    : round(self.anomaly_count / max(self.total_sessions, 1) * 100, 1),
            'threshold'       : TRAINING_THRESHOLD,
        }


detector = BehaviorAnomalyDetector()