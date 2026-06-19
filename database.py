import sqlite3
import os
import json
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet

DB_PATH  = os.path.join(os.path.dirname(__file__), 'data', 'login_events.db')
KEY_PATH = os.path.join(os.path.dirname(__file__), 'data', 'fernet.key')


def get_cipher():
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    if os.path.exists(KEY_PATH):
        key = open(KEY_PATH, 'rb').read()
    else:
        key = Fernet.generate_key()
        open(KEY_PATH, 'wb').write(key)
    return Fernet(key)


cipher = get_cipher()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS login_events (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT,
            username_hash TEXT,
            ip_hash       TEXT,
            threat_level  TEXT,
            anomaly_score REAL,
            is_anomaly    INTEGER,
            confidence    REAL,
            blocked       INTEGER DEFAULT 0,
            payload_enc   TEXT
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip_hash    TEXT PRIMARY KEY,
            reason     TEXT,
            blocked_at TEXT
        )
    ''')
    conn.commit()
    conn.close()


SALT = "ueba_2026_x7f2a9_secure_salt"

def save_event(username, ip, result, features_dict):
    username_hash = hashlib.sha256((username + SALT).encode()).hexdigest()[:16]
    ip_hash       = hashlib.sha256((ip + SALT).encode()).hexdigest()[:16]
    payload       = cipher.encrypt(json.dumps(features_dict).encode()).decode()

    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        INSERT INTO login_events
        (timestamp, username_hash, ip_hash, threat_level,
         anomaly_score, is_anomaly, confidence, payload_enc)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.now().isoformat(),
        username_hash,
        ip_hash,
        result.get('threat_level', 'UNKNOWN'),
        result.get('anomaly_score', 0),
        1 if result.get('is_anomaly') else 0,
        result.get('confidence', 0),
        payload,
    ))
    conn.commit()
    conn.close()
def save_blocked_ip(ip_hash, reason):
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        INSERT OR REPLACE INTO blocked_ips (ip_hash, reason, blocked_at)
        VALUES (?, ?, ?)
    ''', (ip_hash, reason, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def get_blocked_ips():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute('SELECT ip_hash, reason, blocked_at FROM blocked_ips ORDER BY blocked_at DESC').fetchall()
    conn.close()
    return [{'ip_hash': r[0], 'reason': r[1], 'blocked_at': r[2]} for r in rows]


def get_recent_events(limit=50):
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.execute('''
        SELECT timestamp, username_hash, ip_hash,
               threat_level, anomaly_score, is_anomaly, confidence, blocked
        FROM login_events
        ORDER BY id DESC LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            'timestamp'    : r[0],
            'username_hash': r[1],
            'ip_hash'      : r[2],
            'threat_level' : r[3],
            'anomaly_score': r[4],
            'is_anomaly'   : bool(r[5]),
            'confidence'   : r[6],
            'blocked'      : bool(r[7]),
        }
        for r in rows
    ]


def get_stats():
    conn      = sqlite3.connect(DB_PATH)
    total     = conn.execute('SELECT COUNT(*) FROM login_events').fetchone()[0]
    anomalies = conn.execute('SELECT COUNT(*) FROM login_events WHERE is_anomaly=1').fetchone()[0]
    blocked   = conn.execute('SELECT COUNT(*) FROM blocked_ips').fetchone()[0]
    by_level  = conn.execute('''
        SELECT threat_level, COUNT(*) FROM login_events GROUP BY threat_level
    ''').fetchall()
    conn.close()
    return {
        'total'    : total,
        'anomalies': anomalies,
        'normal'   : total - anomalies,
        'blocked'  : blocked,
        'by_level' : {r[0]: r[1] for r in by_level},
    }


init_db()