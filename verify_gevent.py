import requests
import json
import threading
import time

BASE_URL = "http://localhost:8080"

def start_scan(tool, target):
    url = f"{BASE_URL}/api/scan"
    payload = {"tool": tool, "target": target}
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(url, json=payload, headers=headers)
        print(f"[SCAN] Started {tool} for {target}: {response.json()}")
    except Exception as e:
        print(f"[SCAN] Error starting {tool}: {e}")

def generate_exploit():
    url = f"{BASE_URL}/api/generate_exploit"
    payload = {"vuln": "Exposed Redis Instance", "target": "127.0.0.1"}
    headers = {"Content-Type": "application/json"}
    try:
        print("[AI] Requesting exploit generation...")
        response = requests.post(url, json=payload, headers=headers)
        data = response.json()
        if data.get("status") == "success":
            print(f"[AI] Success! Script length: {len(data.get('code', ''))}")
        else:
            print(f"[AI] Failed: {data}")
    except Exception as e:
        print(f"[AI] Error: {e}")

if __name__ == "__main__":
    threads = []

    # Trigger 3 concurrent scans
    scans = [
        ("Nmap", "127.0.0.1"),
        ("WhatWeb", "localhost"),
        ("nikto", "127.0.0.1")
    ]

    for tool, target in scans:
        t = threading.Thread(target=start_scan, args=(tool, target))
        threads.append(t)
        t.start()

    # Trigger AI exploit generation
    t_ai = threading.Thread(target=generate_exploit)
    threads.append(t_ai)
    t_ai.start()

    for t in threads:
        t.join()

    print("\n[VERIFICATION] All test triggers sent. Checking status...")

    # Wait a bit for the background tasks to reflect in jobs
    time.sleep(2)
    response = requests.get(f"{BASE_URL}/api/jobs")
    print(f"[VERIFICATION] Current Jobs: {json.dumps(response.json(), indent=2)}")
