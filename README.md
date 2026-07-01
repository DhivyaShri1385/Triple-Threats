# 🛡 Real-Time User Behavioral Analysis for Anomaly Detection

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![ML](https://img.shields.io/badge/ML-Isolation%20Forest-orange)
![Security](https://img.shields.io/badge/Encryption-AES--256-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

A production-grade cybersecurity platform that detects anomalous login behavior in real time using machine learning — without any predefined dataset. The system captures 25 behavioral biometric signals per session and builds a per-user Isolation Forest model that detects impersonation, bot attacks, and brute force attempts automatically.

---

## 🚀 What Makes This Different

| Traditional IDS | This Project |
|---|---|
| Predefined 2009 dataset (NSL-KDD) | Generates own real-time behavioral data |
| Offline batch prediction | Real-time per-keystroke analysis |
| Network packet features | Behavioral biometric features |
| Static model | Self-learning per-user profiling |
| No live UI | Professional SOC dashboard |

---

## ✨ Features

- **25 behavioral signals** — keystroke dynamics, mouse behavior, device fingerprint
- **Per-user Isolation Forest** — each user has their own behavioral baseline
- **Real-time scoring** — every login session scored in under 2 seconds
- **Impersonation detection** — correct password, wrong typing pattern = flagged
- **Bot detection** — headless browser signals, zero hesitation patterns
- **AES-256 encryption** — all session records encrypted at rest
- **SHA-256 pseudonymization** — no raw identifiers stored anywhere
- **Automated email alerts** — SMTP alert fires on CRITICAL detection
- **Professional SOC dashboard** — live feed, charts, behavioral gauges
- **PDF report download** — admin-only session report generation
- **Brute force protection** — auto-block after 5 failed attempts
- **GDPR compliant** — no raw personal data stored

---

## 🏗 System Architecture

Login page (behavioral capture)

↓

25 features extracted

(keystroke + mouse + device)

↓

SHA-256 pseudonymization

↓

Per-user Isolation Forest scoring

↓

┌─────────────────────────────┐

│  NORMAL  → Session allowed  │

│  LOW     → Logged           │

│  MEDIUM  → Flagged          │

│  HIGH    → Email alert      │

│  CRITICAL→ Block + alert    │

└─────────────────────────────┘

↓

AES-256 encrypted SQLite storage

↓

SOC dashboard live update

---

## 📊 Behavioral Features Captured

### Keystroke Dynamics (8 features)
- Dwell time mean and standard deviation
- Flight time mean and standard deviation
- Typing speed (keys per second)
- Rhythm consistency
- Error rate (backspace frequency)
- Key count

### Mouse Behavior (7 features)
- Velocity mean and standard deviation
- Acceleration
- Click count
- Hesitation count
- Movement linearity
- Double click speed

### Device Fingerprint (10 features)
- Screen width and height
- Timezone offset
- Language count
- Plugin count
- Touch support
- Color depth
- CPU cores
- Device fingerprint hash
- Headless browser signals

---

## 🔐 Security Implementation

| Concept | Implementation |
|---|---|
| Confidentiality | SHA-256 pseudonymization + AES-256 Fernet encryption |
| Integrity | Per-user behavioral verification on every login |
| Availability | Brute force lockout + auto-block on CRITICAL |
| Zero-day detection | Isolation Forest learns normal, flags unknown patterns |
| GDPR compliance | No raw personal data stored anywhere |

---

## 🛠 Tech Stack

| Category | Technology |
|---|---|
| Language | Python 3.12 |
| Web framework | Flask 3.0 |
| Machine learning | scikit-learn — Isolation Forest |
| Encryption | cryptography — AES-256 Fernet |
| Hashing | hashlib — SHA-256 |
| Database | SQLite3 |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Charts | Chart.js 4.4 |
| Email alerts | smtplib — Gmail SMTP |
| Tunneling | ngrok 3.39 |
| Version control | Git + GitHub |

---

## ⚙️ Setup and Installation

### Prerequisites
- Python 3.12+
- pip

### Install dependencies
```bash
pip install flask flask-cors scikit-learn numpy cryptography
```

### Configure email alerts
```bash
cp alert_system_template.py alert_system.py
```
Edit `alert_system.py` and fill in your Gmail credentials:
```python
SENDER_EMAIL   = "your_gmail@gmail.com"
SENDER_PASS    = "your_16_char_app_password"
RECEIVER_EMAIL = "your_gmail@gmail.com"
```

### Run the application
```bash
python app.py
```

Open `http://localhost:5000/login`

---

## 👥 Demo Credentials

| Username | Password | Role |
|---|---|---|
| admin | admin@2024 | Administrator |
| analyst | analyst@2024 | SOC Analyst |

---

## 📁 Project Structure
ueba_project/

├── app.py                      # Flask backend — 8 API endpoints

├── behavior_tracker.py         # Real-time feature extraction

├── ml_engine.py                # Per-user Isolation Forest engine

├── database.py                 # AES-256 encrypted SQLite storage

├── alert_system.py             # Email alert (excluded from git)

├── alert_system_template.py    # Safe template for GitHub

├── requirements.txt            # Python dependencies

├── README.md                   # This file

├── .gitignore                  # Excludes credentials and models

├── templates/

│   ├── login.html              # Professional dark navy login page

│   └── dashboard.html          # SOC dashboard with live feed

├── models/                     # Trained ML profiles (excluded)

└── data/                       # SQLite DB and keys (excluded)

---

## 🔒 Security Notes

- `alert_system.py` is excluded from git via `.gitignore` — contains Gmail credentials
- `models/` directory excluded — contains trained behavioral profiles
- `data/` directory excluded — contains encrypted database and Fernet key
- Never commit real credentials to GitHub

---

## 🧪 Attack Scenarios Detected

| Attack | Detection method | Response |
|---|---|---|
| Bot login | Zero hesitation, headless signals | CRITICAL — auto-block |
| Brute force | 5+ failed attempts | IP blocked |
| Impersonation | Different typing rhythm | HIGH/CRITICAL alert |
| Credential stuffing | Identical pattern multiple users | Flagged |
| Off-hours access | Device fingerprint mismatch | Anomaly scored |

---

## ⚠️ Limitations

- Cold start — 30 sessions needed before detection activates
- Behavioral drift — typing changes over time may cause false positives
- Small training set — production systems use hundreds of sessions
- Local deployment — requires ngrok for external access

---

## 🔮 Future Work

- LSTM neural network for sequential temporal modeling
- Federated learning for multi-organization deployment
- Real-time packet capture with Scapy
- Cloud deployment with TLS 1.3
- JWT authentication for dashboard

---

## 👨‍💻 Team

| Member | Role |
|---|---|
| Dhivya Shri S | ML Engineer — model, backend, deployment |
| Priyanka P | Security Analyst — encryption, report |
| Aishwaraya V | UI/UX — frontend, presentation |

**Project Tutor:** Abhishek Chouriya

**College:** M.Kumarasamy College Of Engineering
**Domain:** Cybersecurity — Network Security / Behavioral Biometrics
**Year:** 2025-2026

---

## 📄 License

MIT License — free to use for educational purposes.

## Outcome
## Real-Admin Dashboard
1)Login
<img width="1848" height="872" alt="image" src="https://github.com/user-attachments/assets/12adac3c-1e35-4b10-b91a-85d15fe5a95c" />
2)TechNova Solutions 
<img width="1845" height="875" alt="image" src="https://github.com/user-attachments/assets/12cd30e8-6efd-490d-8a76-709db8e9723e" />
3)Attacker Activity
<img width="1850" height="871" alt="image" src="https://github.com/user-attachments/assets/27003c7d-630f-412b-aabc-570107f73a6b" />
4)Security Operations
<img width="1847" height="1076" alt="image" src="https://github.com/user-attachments/assets/12fca962-368b-4b5c-9bdb-cc18983815ea" />
<img width="1842" height="458" alt="image" src="https://github.com/user-attachments/assets/917a1da5-6361-496a-b21d-558d25dd0259" />

## Fake Dashboard
1)Login
<img width="1848" height="872" alt="image" src="https://github.com/user-attachments/assets/c21d9e4b-6cfe-45e9-8176-cab5330cd019" />
2)Overview
<img width="1845" height="1077" alt="Screenshot 2026-07-01 102737" src="https://github.com/user-attachments/assets/9fb93802-1602-49b5-b692-bea2b656a9d0" />
3)Employees
<img width="1855" height="1072" alt="Screenshot 2026-07-01 102749" src="https://github.com/user-attachments/assets/7b4386c2-0e2d-497f-a862-25450e73cf3f" />
4)Projects
<img width="1853" height="1077" alt="Screenshot 2026-07-01 102758" src="https://github.com/user-attachments/assets/1cb9baa0-17da-46d9-84b6-e9b81df1ff40" />
5)Finance
<img width="1860" height="1075" alt="Screenshot 2026-07-01 102808" src="https://github.com/user-attachments/assets/d8d65541-7569-4b24-bae5-923160b787f0" />

## Alert 
<img width="1498" height="817" alt="image" src="https://github.com/user-attachments/assets/c527e5af-e9fd-4ab0-8f9c-5e6564e43619" />

##  UEBA Security Report 
<img width="1845" height="865" alt="image" src="https://github.com/user-attachments/assets/776f86f5-42ec-4a75-bede-6808244589b6" />


