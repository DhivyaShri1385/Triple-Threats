import numpy as np
import hashlib


def extract_keystroke_features(keystroke_data):
    if not keystroke_data or len(keystroke_data) < 2:
        return [0, 0, 0, 0, 0, 0, 0, 0]

    dwell_times  = []
    flight_times = []
    errors       = 0

    for i, k in enumerate(keystroke_data):
        press   = k.get('press_time')
        release = k.get('release_time')

        if press is None:
            continue

        if k.get('key') in ['Backspace', 'Delete']:
            errors += 1

        if release is not None and isinstance(release, (int, float)):
            dwell = release - press
            if dwell > 0:
                dwell_times.append(dwell)

        if i > 0:
            prev_release = keystroke_data[i-1].get('release_time')
            if (prev_release is not None and
                    isinstance(prev_release, (int, float)) and
                    isinstance(press, (int, float))):
                flight = press - prev_release
                if 0 < flight < 2000:
                    flight_times.append(flight)

    valid = [k for k in keystroke_data if isinstance(k.get('press_time'), (int, float))]
    total_time = 0
    if len(valid) >= 2:
        total_time = (valid[-1]['press_time'] - valid[0]['press_time']) / 1000.0

    typing_speed = len(valid) / total_time if total_time > 0 else 0
    dwell_arr    = np.array(dwell_times)  if dwell_times  else np.array([0])
    flight_arr   = np.array(flight_times) if flight_times else np.array([0])
    rhythm       = 1 - (np.std(flight_arr) / (np.mean(flight_arr) + 1e-9))

    return [
        float(np.mean(dwell_arr)),
        float(np.std(dwell_arr)),
        float(np.mean(flight_arr)),
        float(np.std(flight_arr)),
        float(typing_speed),
        float(np.clip(rhythm, 0, 1)),
        errors / max(len(keystroke_data), 1),
        float(len(keystroke_data)),
    ]


def extract_mouse_features(mouse_data, click_data):
    if not mouse_data or len(mouse_data) < 2:
        return [0, 0, 0, 0, 0, 0, 0]

    velocities  = []
    hesitations = 0

    for i in range(1, len(mouse_data)):
        dx = mouse_data[i]['x'] - mouse_data[i-1]['x']
        dy = mouse_data[i]['y'] - mouse_data[i-1]['y']
        dt = (mouse_data[i]['t'] - mouse_data[i-1]['t']) / 1000.0
        if dt > 0:
            vel = np.sqrt(dx**2 + dy**2) / dt
            velocities.append(vel)
            if vel < 5 and dt > 0.5:
                hesitations += 1

    vel_arr = np.array(velocities) if velocities else np.array([0])

    if len(mouse_data) >= 2:
        start = np.array([mouse_data[0]['x'],  mouse_data[0]['y']])
        end   = np.array([mouse_data[-1]['x'], mouse_data[-1]['y']])
        direct_dist = np.linalg.norm(end - start)
        path_dist   = sum(
            np.sqrt((mouse_data[i]['x'] - mouse_data[i-1]['x'])**2 +
                    (mouse_data[i]['y'] - mouse_data[i-1]['y'])**2)
            for i in range(1, len(mouse_data))
        )
        linearity = direct_dist / (path_dist + 1e-9)
    else:
        linearity = 0

    double_clicks = 0
    for i in range(1, len(click_data)):
        if click_data[i]['t'] - click_data[i-1]['t'] < 300:
            double_clicks += 1

    return [
        float(np.mean(vel_arr)),
        float(np.std(vel_arr)),
        float(np.std(np.diff(vel_arr)) if len(vel_arr) > 1 else 0),
        float(len(click_data)),
        float(hesitations),
        float(np.clip(linearity, 0, 1)),
        float(double_clicks),
    ]


def extract_device_features(device_data):
    ua          = device_data.get('user_agent', '')
    screen_w    = device_data.get('screen_width', 0)
    screen_h    = device_data.get('screen_height', 0)
    timezone    = device_data.get('timezone_offset', 0)
    lang_count  = len(device_data.get('languages', '').split(','))
    plugins     = device_data.get('plugin_count', 0)
    touch       = 1 if device_data.get('touch_support') else 0
    color_depth = device_data.get('color_depth', 24)
    cpu_cores   = device_data.get('cpu_cores', 4)

    fp_string = f"{ua}{screen_w}{screen_h}{timezone}{color_depth}"
    fp_hash   = int(hashlib.md5(fp_string.encode()).hexdigest()[:8], 16) % 10000

    headless = sum([
        'HeadlessChrome' in ua,
        'PhantomJS' in ua,
        plugins == 0,
        screen_w == 0,
    ])

    return [
        float(screen_w),
        float(screen_h),
        float(timezone),
        float(lang_count),
        float(plugins),
        float(touch),
        float(color_depth),
        float(cpu_cores),
        float(fp_hash),
        float(headless),
    ]


def build_feature_vector(keystroke_data, mouse_data, click_data, device_data):
    kf = extract_keystroke_features(keystroke_data)
    mf = extract_mouse_features(mouse_data, click_data)
    df = extract_device_features(device_data)
    return np.array(kf + mf + df, dtype=float)


FEATURE_NAMES = [
    'dwell_time_mean', 'dwell_time_std', 'flight_time_mean', 'flight_time_std',
    'typing_speed', 'rhythm_consistency', 'error_rate', 'key_count',
    'mouse_velocity_mean', 'mouse_velocity_std', 'mouse_acceleration',
    'click_count', 'hesitation_count', 'movement_linearity', 'double_click_speed',
    'screen_width', 'screen_height', 'timezone_offset', 'language_count',
    'plugin_count', 'touch_support', 'color_depth', 'cpu_cores',
    'device_fp_hash', 'headless_signals',
]