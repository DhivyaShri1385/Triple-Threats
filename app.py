from alert_system import send_alert
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
import hashlib
import os
import threading
from datetime import datetime

from behavior_tracker import build_feature_vector, FEATURE_NAMES
from ml_engine import detector
from database import save_event, get_recent_events, get_stats, get_blocked_ips

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'realtime-ueba-secret-2024')
CORS(app)

# ── In-memory trackers ────────────────────────────────────────
blocked_ips     = set()
failed_attempts = {}

USERS = {
    'admin'  : hashlib.sha256('admin@2024'.encode()).hexdigest(),
    'analyst': hashlib.sha256('analyst@2024'.encode()).hexdigest(),
}
TRUSTED_DEVICE_FP = None  # set after first real admin login
THREAT_COLORS = {
    'CRITICAL': '#ff0040',
    'HIGH'    : '#ff4444',
    'MEDIUM'  : '#ff9900',
    'LOW'     : '#ffff00',
    'NORMAL'  : '#00ff41',
    'LEARNING': '#00d4ff',
}


SALT = "ueba_2026_x7f2a9_secure_salt"

def sha256(val):
    salted = str(val) + SALT
    return hashlib.sha256(salted.encode()).hexdigest()[:16]


def get_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr)


# ── ROUTES ────────────────────────────────────────────────────
@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return redirect(url_for('dashboard'))


@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login_page'))
    if _is_trusted_admin():
        return render_template('dashboard.html')
    log_attacker_view(session.get('user', 'unknown'), get_ip())
    return render_template('fake_dashboard.html')


# ── API ───────────────────────────────────────────────────────
@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.json or {}
    ip   = get_ip()

    if False:
        return jsonify({
            'blocked'     : True,
            'threat_level': 'CRITICAL',
            'message'     : 'IP blocked due to suspicious behavior',
        }), 403

    keystroke_data = data.get('keystrokes',   [])
    mouse_data     = data.get('mouse_moves',  [])
    click_data     = data.get('clicks',       [])
    device_data    = data.get('device',       {})
    username       = data.get('username',     'unknown')
    attempt_num    = data.get('attempt_number', 1)

    try:
        features = build_feature_vector(
            keystroke_data, mouse_data, click_data, device_data
        )
    except Exception:
        import numpy as np
        features = np.zeros(25)

    is_submit = attempt_num > 0 and len(keystroke_data) > 5
    if is_submit:
        result = detector.score(features, username=username)
    else:
        result = {
            'status'        : 'monitoring',
            'anomaly_score' : None,
            'is_anomaly'    : False,
            'threat_level'  : 'LEARNING',
            'confidence'    : 0,
            'message'       : 'Monitoring behavior...',
        }
        
    result['ip_hash']        = sha256(ip)
    result['username_hash']  = sha256(username)
    result['timestamp']      = datetime.now().strftime('%H:%M:%S')
    result['attempt_number'] = attempt_num
    result['color']          = THREAT_COLORS.get(result['threat_level'], '#00ff41')

    result['features'] = {
        'typing_speed'       : round(float(features[4]), 2),
        'rhythm_consistency' : round(float(features[5]), 3),
        'dwell_time_mean'    : round(float(features[0]), 1),
        'flight_time_mean'   : round(float(features[2]), 1),
        'mouse_velocity'     : round(float(features[8]), 1),
        'hesitations'        : int(features[12]),
        'movement_linearity' : round(float(features[13]), 3),
        'headless_signals'   : int(features[24]),
        'device_fp'          : str(int(features[22])),
    }

    if result.get('threat_level') == 'CRITICAL':
        blocked_ips.add(sha256(ip))
        result['auto_blocked'] = True
        from database import save_blocked_ip
        save_blocked_ip(sha256(ip), 'CRITICAL anomaly score detected')

    ip_key = sha256(ip)
    failed_attempts[ip_key] = failed_attempts.get(ip_key, 0) + (1 if attempt_num > 1 else 0)
    if failed_attempts.get(ip_key, 0) >= 5:
        blocked_ips.add(ip_key)
        result['brute_force_blocked'] = True
        result['threat_level']        = 'CRITICAL'

    features_dict = {FEATURE_NAMES[i]: float(features[i]) for i in range(len(features))}
    threading.Thread(
        target=save_event,
        args=(username, ip, result, features_dict),
        daemon=True
    ).start()

    if result.get('threat_level') in ['CRITICAL', 'HIGH']:
        threading.Thread(target=send_alert, args=(result,), daemon=True).start()

    return jsonify(result)


@app.route('/api/login_submit', methods=['POST'])
def login_submit():
    global TRUSTED_DEVICE_FP
    data          = request.json or {}
    username      = data.get('username', '')
    password      = data.get('password', '')
    device_fp     = data.get('device_fp', '')
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if username in USERS and USERS[username] == password_hash:
        session['user']       = username
        session['login_time'] = datetime.now().isoformat()

        is_real_admin = False
        if username == 'admin':
            if TRUSTED_DEVICE_FP is None:
                TRUSTED_DEVICE_FP = device_fp
                is_real_admin = True
            elif device_fp == TRUSTED_DEVICE_FP:
                is_real_admin = True

        session['is_real_admin'] = is_real_admin
        return jsonify({'success': True, 'redirect': '/dashboard'})

    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})


@app.route('/api/me')
def me():
    if 'user' not in session:
        return jsonify({'authenticated': False}), 401
    return jsonify({
        'authenticated' : True,
        'username'      : session['user'],
        'is_real_admin' : session.get('is_real_admin', False),
    })

import random

def _is_trusted_admin():
    return session.get('user') == 'admin' and session.get('is_real_admin', False)

def _fake_events(n=50):
    levels = ['NORMAL'] * 14 + ['LOW'] * 4 + ['MEDIUM'] * 2
    out = []
    for i in range(n):
        lvl = random.choice(levels)
        out.append({
            'timestamp'    : datetime.now().isoformat(),
            'username_hash': sha256(f'decoy_{random.randint(1000,9999)}'),
            'ip_hash'      : sha256(f'decoy_ip_{random.randint(1000,9999)}'),
            'threat_level' : lvl,
            'anomaly_score': round(random.uniform(0.05, 0.3), 4),
            'is_anomaly'   : False,
            'confidence'   : round(random.uniform(60, 95), 1),
            'blocked'      : False,
        })
    return out

def _fake_blocked_ips():
    return []

def _fake_stats():
    total = random.randint(40, 90)
    return {
        'total'           : total,
        'anomalies'       : random.randint(0, 2),
        'normal'          : total - random.randint(0, 2),
        'blocked'         : 0,
        'by_level'        : {'NORMAL': total},
        'is_trained'      : True,
        'training_samples': 30,
        'total_sessions'  : total,
        'anomaly_count'   : random.randint(0, 2),
        'anomaly_rate'    : round(random.uniform(0, 4), 1),
        'threshold'       : 30,
        'profiles'        : {},
        'blocked_ips'     : 0,
    }

def _fake_team():
    names = ['Rahul Mehta', 'Sneha Iyer', 'Vikram Rao', 'Anjali Nair', 'Karthik S',
              'Divya Pillai', 'Arjun Kapoor', 'Meera Sundar']
    roles = ['Senior Software Engineer', 'Product Manager', 'DevOps Engineer',
              'UI/UX Designer', 'QA Lead', 'Backend Developer', 'Data Analyst', 'HR Manager']
    depts = ['Engineering', 'Product', 'Engineering', 'Design', 'Quality', 'Engineering', 'Analytics', 'HR']
    cities = ['Chennai', 'Bangalore', 'Hyderabad', 'Pune', 'Mumbai', 'Coimbatore', 'Kochi', 'Delhi']
    out = []
    for i in range(8):
        out.append({
            'name'       : names[i],
            'role'       : roles[i],
            'department' : depts[i],
            'salary'     : random.choice([45000, 62000, 78000, 95000, 110000, 135000]),
            'address'    : f'{random.randint(10,400)} {random.choice(["MG Road","Anna Salai","Park Street","Brigade Road"])}, {cities[i]}',
            'email'      : names[i].lower().replace(' ', '.') + '@technova.com',
            'status'     : random.choice(['Active', 'Active', 'On Leave']),
            'joined'     : f'20{random.randint(19,24)}-0{random.randint(1,9)}-{random.randint(10,28)}',
        })
    return out

def _fake_projects():
    names = ['Project Phoenix', 'CloudSync v2', 'Mobile Revamp', 'API Gateway',
              'Customer Portal', 'Analytics Engine']
    statuses = ['In Progress', 'In Progress', 'Completed', 'Planning', 'In Progress', 'Review']
    out = []
    for i, n in enumerate(names):
        out.append({
            'name'     : n,
            'status'   : statuses[i],
            'progress' : random.randint(20, 95),
            'budget'   : random.choice([250000, 480000, 620000, 890000, 1200000]),
            'deadline' : f'2026-0{random.randint(7,9)}-{random.randint(10,28)}',
            'lead'     : random.choice(['Rahul Mehta', 'Sneha Iyer', 'Vikram Rao', 'Karthik S']),
        })
    return out

def _fake_business_stats():
    return {
        'revenue'        : random.randint(2800000, 4200000),
        'revenue_growth' : round(random.uniform(8, 22), 1),
        'employees'      : 8,
        'active_projects': random.randint(4, 6),
        'monthly_trend'  : [random.randint(180000, 420000) for _ in range(7)],
    }
def _real_company_data():
    """Static REAL company data — edit these values with actual info"""
    return {
        'team': [
            {'name': 'Dhivya Shri S', 'role': 'ML Engineer & Team Lead', 'department': 'Engineering',
             'salary': 0, 'address': 'M.Kumarasamy College of Engineering, Karur',
             'email': 'dhivyashri@mkce.ac.in', 'status': 'Active', 'joined': '2025-08-01'},
            {'name': 'Priyanka P', 'role': 'Security Analyst', 'department': 'Security',
             'salary': 0, 'address': 'M.Kumarasamy College of Engineering, Karur',
             'email': 'priyanka@mkce.ac.in', 'status': 'Active', 'joined': '2025-08-01'},
            {'name': 'Aishwaraya V', 'role': 'UI/UX Lead', 'department': 'Design',
             'salary': 0, 'address': 'M.Kumarasamy College of Engineering, Karur',
             'email': 'aishwaraya@mkce.ac.in', 'status': 'Active', 'joined': '2025-08-01'},
        ],
        'projects': [
            {'name': 'Real-Time UEBA Platform', 'status': 'In Progress', 'progress': 92,
             'budget': 0, 'deadline': '2026-06-20', 'lead': 'Dhivya Shri S'},
            {'name': 'Behavioral Biometric Engine', 'status': 'Completed', 'progress': 100,
             'budget': 0, 'deadline': '2026-06-15', 'lead': 'Dhivya Shri S'},
            {'name': 'SOC Dashboard & Honeypot System', 'status': 'In Progress', 'progress': 88,
             'budget': 0, 'deadline': '2026-06-20', 'lead': 'Priyanka P'},
        ],
        'business_stats': {
            'revenue': 0,
            'revenue_growth': 0,
            'employees': 3,
            'active_projects': 2,
            'monthly_trend': [0, 0, 0, 0, 0, 0, 0],
        }
    }

# Tracks attacker sessions that hit the fake dashboard
attacker_log = []

def log_attacker_view(username, ip):
    attacker_log.append({
        'timestamp'    : datetime.now().isoformat(),
        'username_hash': sha256(username),
        'ip_hash'      : sha256(ip),
        'page'         : 'fake_dashboard',
    })

@app.route('/api/events')
def events():
    if not _is_trusted_admin():
        return jsonify(_fake_events(50))
    return jsonify(get_recent_events(50))


@app.route('/api/blocked_ips')
def blocked_ips_api():
    if not _is_trusted_admin():
        return jsonify(_fake_blocked_ips())
    from database import get_blocked_ips
    return jsonify(get_blocked_ips())


@app.route('/api/stats')
def stats():
    if not _is_trusted_admin():
        return jsonify(_fake_stats())
    db_stats = get_stats()
    ml_stats = detector.get_stats()
    return jsonify({
        **db_stats,
        **ml_stats,
        'blocked_ips': len(blocked_ips),
    })

@app.route('/api/team')
def team_api():
    return jsonify(_fake_team())

@app.route('/api/projects')
def projects_api():
    return jsonify(_fake_projects())

@app.route('/api/business_stats')
def business_stats_api():
    return jsonify(_fake_business_stats())

@app.route('/api/real_company')
def real_company_api():
    if not _is_trusted_admin():
        return jsonify({'error': 'forbidden'}), 403
    return jsonify(_real_company_data())

@app.route('/api/attacker_log')
def attacker_log_api():
    if not _is_trusted_admin():
        return jsonify({'error': 'forbidden'}), 403
    return jsonify(list(reversed(attacker_log)))

@app.route('/api/model_status')
def model_status():
    return jsonify(detector.get_stats())

if __name__ == '__main__':
    print("\n" + "="*50)
    print("  Real-Time UEBA Platform")
    print("="*50)
    print("  Login     : http://localhost:5000/login")
    print("  Dashboard : http://localhost:5000/dashboard")
    print("="*50 + "\n")
    app.run(debug=True, port=5000, threaded=True)