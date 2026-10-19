import hashlib
import os
import sys
import time

import requests

#Base configuration
BASE = os.getenv("BACKEND_URL", "http://127.0.0.1:5000")
API_KEY = os.getenv("API_KEY", "")
HEADERS = {"X-API-Key": API_KEY} if API_KEY else {}

POLL_EVERY = 30  #Time interval (seconds) between result polling requests
GIVE_UP = 600    #Maximum wait timeout (seconds)

def sha256_of(path: str) -> str:
    # Calculate SHA-256 cryptographic digest of a local file.
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    path = sys.argv[1]
    mode = (sys.argv[2] if len(sys.argv) > 2 else "B").upper()

    if not os.path.isfile(path):
        print(f"[ERROR] File not found: {path}")
        sys.exit(1)

    filename = os.path.basename(path)
    digest = sha256_of(path)

    print("==================================================")
    print("      Hash-to-Sandbox Test Client Execution       ")
    print("==================================================")
    print(f"File     : {filename}")
    print(f"SHA-256  : {digest}")
    print(f"Mode     : {mode}")
    print(f"Backend  : {BASE}\n")

    t0 = time.perf_counter()

    # Step 1: Send SHA-256 Hash Inspection Request
    try:
        r = requests.post(
            f"{BASE}/inspect",
            json={"sha256": digest, "filename": filename, "mode": mode},
            headers=HEADERS,
            timeout=30,
        )
        r.raise_for_status()
    except requests.RequestException as e:
        print(f"[ERROR] Failed to connect to Backend at {BASE}/inspect: {e}")
        sys.exit(1)

    data = r.json()
    print(f"[inspect] {data}  ({time.perf_counter() - t0:.2f} s)")

    if data.get("verdict") != "NEED_FILE":
        print(f"\n[FINISHED] Direct verdict resolved via static hash lookup: {data.get('verdict')}")
        return

    # Step 2: Upload File Binary to Backend (Forwarded to CAPEv2 Sandbox)
    print("\n[INFO] Hash unknown or Mode A active. Uploading binary payload to CAPEv2...")
    try:
        with open(path, "rb") as f:
            r = requests.post(
                f"{BASE}/submit",
                files={"file": (filename, f)},
                data={"mode": mode},
                headers=HEADERS,
                timeout=120,
            )
        r.raise_for_status()
    except requests.RequestException as e:
        print(f"[ERROR] Failed to submit file to backend: {e}")
        sys.exit(1)

    data = r.json()
    print(f"[submit]  {data}  ({time.perf_counter() - t0:.2f} s)")

    if data.get("verdict") != "PENDING":
        print(f"\n[FINISHED] Submission ended with verdict: {data.get('verdict')} - {data.get('reason')}")
        return

    # Step 3: Poll CAPEv2 Task Execution Results
    task_id = data["task_id"]
    print(f"\n[INFO] Task registered on CAPEv2 (Task ID: {task_id}). Polling for analysis report...\n")

    while time.perf_counter() - t0 < GIVE_UP:
        time.sleep(POLL_EVERY)
        try:
            r = requests.get(f"{BASE}/result/{task_id}", headers=HEADERS, timeout=30)
            r.raise_for_status()
            data = r.json()
        except requests.RequestException as e:
            print(f"[WARN] Status check request failed: {e}. Retrying in {POLL_EVERY}s...")
            continue

        elapsed = time.perf_counter() - t0
        print(f"[result]  {data}  ({elapsed:.0f} s elapsed)")

        if data.get("verdict") != "PENDING":
            print("--------------------------------------------------")
            print(f" FINAL VERDICT : {data.get('verdict')}")
            if "malscore" in data:
                print(f" MALscore      : {data.get('malscore')}")
            if "reason" in data:
                print(f" Reason        : {data.get('reason')}")
            print(f" Total Time    : {elapsed:.1f} seconds")
            print("--------------------------------------------------")
            return

    print("\n[TIMEOUT] Stopped polling: exceeded maximum wait time threshold.")


if __name__ == "__main__":
    main()
