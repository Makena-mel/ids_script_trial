import time
import re
from collections import defaultdict, deque
import statistics

# Configuration
LOG_FILE = "auth.log"
FAIL_REGEX = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")
THRESHOLD = 5
TIME_WINDOW = 50

# Signature-based detection patterns (examples for log-based IDS)
SIGNATURES = [
    re.compile(r"SELECT .* FROM .*", re.IGNORECASE),  # SQL injection
    re.compile(r"<script>.*</script>", re.IGNORECASE),  # XSS
    re.compile(r"eval\(.*\)", re.IGNORECASE),  # Code injection
    re.compile(r"rm -rf /", re.IGNORECASE),  # Dangerous command
]

# Anomaly detection parameters
ANOMALY_WINDOW = 100  # Number of recent events to consider
ANOMALY_THRESHOLD = 2.0  # Z-score threshold for anomaly

failed_attempts = defaultdict(list)
event_times = deque(maxlen=ANOMALY_WINDOW)

def alert_signature(ip, signature):
    print(f"[!] SIGNATURE ALERT: Detected known attack pattern '{signature}' from {ip}!")

def alert_anomaly(ip, reason):
    print(f"[!] ANOMALY ALERT: {reason} from {ip}!")

def alert_brute_force(ip):
    print(f"[!] BRUTE FORCE ALERT: Multiple failed login attempts from {ip}!")

def simulate_log_read():
    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                yield line
                time.sleep(0.5)  # Simulate real-time arrival
    except FileNotFoundError:
        print(f"[!] Log file {LOG_FILE} not found. Please ensure the log file exists.")
        return

def check_signatures(line, ip=None):
    for sig in SIGNATURES:
        if sig.search(line):
            alert_signature(ip or "unknown", sig.pattern)
            return True
    return False

def check_anomaly(current_time):
    if len(event_times) < 10:  # Need some data
        return False
    mean = statistics.mean(event_times)
    stdev = statistics.stdev(event_times)
    if stdev == 0:
        return False
    z_score = (current_time - mean) / stdev
    if abs(z_score) > ANOMALY_THRESHOLD:
        alert_anomaly("system", f"Unusual event timing (z-score: {z_score:.2f})")
        return True
    return False

def check_line(line, current_time):
    # Extract IP if possible
    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
    ip = ip_match.group(1) if ip_match else None

    # Signature-based check
    check_signatures(line, ip)

    # Brute force anomaly (threshold-based)
    match = FAIL_REGEX.search(line)
    if match:
        ip = match.group(1)
        failed_attempts[ip].append(current_time)

        # Clean old attempts
        failed_attempts[ip] = [t for t in failed_attempts[ip] if current_time - t < TIME_WINDOW]

        if len(failed_attempts[ip]) >= THRESHOLD:
            alert_brute_force(ip)
            failed_attempts[ip].clear()

    # General anomaly detection on event timing
    event_times.append(current_time)
    check_anomaly(current_time)

def main():
    print(f"[*] IDS monitoring {LOG_FILE} with signature-based and anomaly detection...\n")
    for line in simulate_log_read():
        now = time.time()
        check_line(line, now)

if __name__ == "__main__":
    main()



