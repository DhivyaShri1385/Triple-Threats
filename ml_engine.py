import numpy as np
import pickle
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MODEL_DIR  = os.path.join(os.path.dirname(__file__), 'models')
TRAINING_THRESHOLD = 15
ANOMALY_THRESHOLD  = -0.25

class UserBehaviorProfile:
    def __init__(self, username):
        self.username      = username
        self.model         = None
        self.scaler        = StandardScaler()
        self.training_data = []
        self.is_trained    = False
        self.total         = 0
        self.anomalies     = 0

    def add_sample(self, vector):
        self.training_data.append(vector)
        if len(self.training_data) >= TRAINING_THRESHOLD:
            self._train()

    def _train(self):
        X        = np.array(self.training_data)
        self.scaler  = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        self.model   = IsolationForest(
            n_estimators=100, contamination=0.15,max_samples=256, 
            random_state=42, n_jobs=-1
        )
        self.model.fit(X_scaled)
        self.is_trained = True
        print(f"Profile trained for user: {self.username}")

    def score(self, vector):
        self.total += 1
        if not self.is_trained:
            self.add_sample(vector)
            needed = TRAINING_THRESHOLD - len(self.training_data)
            return {
                'status'          : 'learning',
                'anomaly_score'   : None,
                'is_anomaly'      : False,
                'threat_level'    : 'LEARNING',
                'confidence'      : 0,
                'sessions_needed' : max(needed, 0),
                'message'         : f'Building your profile... {len(self.training_data)}/{TRAINING_THRESHOLD}',
            }

        X_scaled   = self.scaler.transform(vector.reshape(1, -1))
        score      = float(self.model.score_samples(X_scaled)[0])
        pred       = self.model.predict(X_scaled)[0]
        is_anomaly = pred == -1 or score < ANOMALY_THRESHOLD

        if is_anomaly:
            self.anomalies += 1

        if score < -0.3:
            threat = 'CRITICAL'
            confidence = min(abs(score) * 200, 99)
        elif score < -0.2:
            threat = 'HIGH'
            confidence = min(abs(score) * 150, 90)
        elif score < -0.1:
            threat = 'MEDIUM'
            confidence = min(abs(score) * 100, 75)
        elif score < 0:
            threat = 'LOW'
            confidence = min(abs(score) * 80, 50)
        else:
            threat = 'NORMAL'
            confidence = min(score * 100, 99)

        messages = {
            'CRITICAL': 'Highly anomalous — possible impersonation or bot',
            'HIGH'    : 'Significant deviation from your normal pattern',
            'MEDIUM'  : 'Unusual behavior detected — monitoring',
            'LOW'     : 'Slight deviation — within acceptable range',
            'NORMAL'  : 'Behavior matches your established profile',
        }

        return {
            'status'        : 'active',
            'anomaly_score' : round(score, 4),
            'is_anomaly'    : bool(is_anomaly),
            'confidence'    : round(confidence, 1),
            'threat_level'  : threat,
            'total'         : self.total,
            'anomalies'     : self.anomalies,
            'anomaly_rate'  : round(self.anomalies / self.total * 100, 1),
            'message'       : messages.get(threat, 'Unknown'),
        }


class BehaviorAnomalyDetector:
    def __init__(self):
        self.profiles       = {}
        self.total_sessions = 0
        self.anomaly_count  = 0
        self.load_all()

    def _model_path(self, username):
        return os.path.join(MODEL_DIR, f'profile_{username}.pkl')

    def load_all(self):
        os.makedirs(MODEL_DIR, exist_ok=True)
        for f in os.listdir(MODEL_DIR):
            if f.startswith('profile_') and f.endswith('.pkl'):
                username = f[8:-4]
                try:
                    self.profiles[username] = pickle.load(
                        open(self._model_path(username), 'rb'))
                    print(f"Loaded profile: {username}")
                except:
                    pass

    def save_profile(self, username):
        if username in self.profiles:
            pickle.dump(self.profiles[username],
                       open(self._model_path(username), 'wb'))

    def get_profile(self, username):
        if username not in self.profiles:
            self.profiles[username] = UserBehaviorProfile(username)
        return self.profiles[username]

    def score(self, feature_vector, username='unknown'):
        self.total_sessions += 1
        profile = self.get_profile(username)
        result  = profile.score(feature_vector)

        if result.get('is_anomaly'):
            self.anomaly_count += 1

        if profile.is_trained:
            self.save_profile(username)

        result['username']       = username
        result['total_sessions'] = self.total_sessions
        result['anomaly_count']  = self.anomaly_count
        result['anomaly_rate']   = round(
            self.anomaly_count / self.total_sessions * 100, 1)
        return result

    def get_stats(self):
        profiles_info = {}
        for uname, profile in self.profiles.items():
            profiles_info[uname] = {
                'is_trained'      : profile.is_trained,
                'training_samples': len(profile.training_data),
                'total'           : profile.total,
                'anomalies'       : profile.anomalies,
            }
        return {
            'is_trained'      : any(p.is_trained for p in self.profiles.values()),
            'training_samples': sum(len(p.training_data) for p in self.profiles.values()),
            'total_sessions'  : self.total_sessions,
            'anomaly_count'   : self.anomaly_count,
            'anomaly_rate'    : round(self.anomaly_count / max(self.total_sessions, 1) * 100, 1),
            'threshold'       : TRAINING_THRESHOLD,
            'profiles'        : profiles_info,
        }


detector = BehaviorAnomalyDetector()