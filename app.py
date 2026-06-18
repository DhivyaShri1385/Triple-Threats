from alert_system import send_alert
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
import hashlib
import os
import threading
from datetime import datetime

from behavior_tracker import build_feature_vector, FEATURE_NAMES
from ml_engine import detector
from database import save_event, get_recent_events, get_stats

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

THREAT_COLORS = {
    'CRITICAL': '#ff0040',
    'HIGH'    : '#ff4444',
    'MEDIUM'  : '#ff9900',
    'LOW'     : '#ffff00',
    'NORMAL'  : '#00ff41',
    'LEARNING': '#00d4ff',
}


def sha256(val):
    return hashlib.sha256(str(val).encode()).hexdigest()[:16]


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
    return render_template('dashboard.html')


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
    data          = request.json or {}
    username      = data.get('username', '')
    password      = data.get('password', '')
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if username in USERS and USERS[username] == password_hash:
        session['user']       = username
        session['login_time'] = datetime.now().isoformat()
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
    return jsonify({'authenticated': True, 'username': session['user']})


@app.route('/api/events')
def events():
    return jsonify(get_recent_events(50))


@app.route('/api/stats')
def stats():
    db_stats = get_stats()
    ml_stats = detector.get_stats()
    return jsonify({
        **db_stats,
        **ml_stats,
        'blocked_ips': len(blocked_ips),
    })


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