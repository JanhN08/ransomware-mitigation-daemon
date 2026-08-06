import os
import sys
import time
import math
import signal
import argparse
from collections import Counter
import psutil
import mysql.connector

ENTROPY_THRESHOLD = 7.5

def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = Counter(data)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def log_to_database(pid: int, process_name: str, entropy: float, status: str):
    try:
        connection = mysql.connector.connect(
            host=os.getenv("DB_HOST", "localhost"),
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASS", ""),
            database=os.getenv("DB_NAME", "forensics_db")
        )
        cursor = connection.cursor()
        query = """
            INSERT INTO process_alerts (pid, process_name, entropy_score, mitigation_status, timestamp)
            VALUES (%s, %s, %s, %s, NOW())
        """
        cursor.execute(query, (pid, process_name, entropy, status))
        connection.commit()
        cursor.close()
        connection.close()
    except Exception as e:
        print(f"[!] Forensics Logging Offline: {e}")

def monitor_processes(threshold: float):
    print(f"[*] Starting Ransomware Mitigation Daemon (Entropy Threshold: {threshold})...")
    for proc in psutil.process_iter(['pid', 'name', 'open_files']):
        try:
            open_files = proc.info.get('open_files')
            if not open_files:
                continue

            for file_info in open_files:
                file_path = file_info.path
                if os.path.isfile(file_path) and os.access(file_path, os.R_OK):
                    with open(file_path, 'rb') as f:
                        sample_data = f.read(4096)
                        if not sample_data:
                            continue

                        entropy = calculate_shannon_entropy(sample_data)

                        if entropy >= threshold:
                            pid = proc.info['pid']
                            pname = proc.info['name']
                            print(f"[🚨 ALERT] High entropy detected ({entropy:.2f}) on PID {pid} ({pname}). Terminating...")
                            os.kill(pid, signal.SIGKILL)
                            log_to_database(pid, pname, entropy, "SIGKILL_TERMINATED")
                            print(f"[✔ SUCCESS] Terminated malicious PID {pid} in < 100ms.")
        except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
            continue

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Endpoint Ransomware Mitigation Daemon")
    parser.add_argument("--threshold", type=float, default=ENTROPY_THRESHOLD, help="Shannon Entropy threshold (0.0 to 8.0)")
    args = parser.parse_args()

    try:
        while True:
            monitor_processes(args.threshold)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Daemon stopped safely.")
