import csv
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from hashlib import sha256 as _sha256
from typing import Optional

import requests
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ---------- Configuration (Environment Variables) ----------
CAPE_URL = os.getenv("CAPE_URL", "http://100.98.98.28:8000").rstrip("/")
#The token is read ONLY from the environment (set it in run_backend.bat).
CAPE_TOKEN = os.getenv("CAPE_TOKEN", "")
CAPE_CHECK_PATH = os.getenv("CAPE_CHECK_PATH", "/apiv2/cuckoo/status/")
DEFAULT_MODE = os.getenv("MODE", "B").upper()  #"A" or "B"
CAPE_TIMEOUT = int(os.getenv("CAPE_TIMEOUT", "120"))  #Sandbox execution timeout in seconds
MAX_WAIT = int(os.getenv("MAX_WAIT", "600"))  #Maximum polling wait time (10 mins)
MAL_THRESHOLD = float(os.getenv("MAL_THRESHOLD", "6.0"))  #Score >= 6.0 -> BLOCK
SAFE_THRESHOLD = float(os.getenv("SAFE_THRESHOLD", "2.0"))  #Score <= 2.0 -> ALLOW
KNOWN_DB = os.getenv("KNOWN_DB", "known_hashes.csv")
LOG_PATH = os.getenv("LOG_PATH", "logs/events.csv")
API_KEY = os.getenv("API_KEY", "") 

#Safely create logging directory if specified
log_dir = os.path.dirname(LOG_PATH)
if log_dir:
    os.makedirs(log_dir, exist_ok=True)

if not CAPE_TOKEN:
    print("[WARN] CAPE_TOKEN is empty: requests to CAPEv2 will be sent without a token.")

app = FastAPI(title="Hash-to-Sandbox Backend")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  #
    allow_methods=["*"],
    allow_headers=["*"],
)

_log_lock = threading.Lock()
TASKS: dict = {}  #task_id -> {"sha256", "mode", "filename", "t0", "final"}


#API KEY CHECK
def check_key(x_api_key: str = Header(default="")):
    if API_KEY and not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")


#Enhanced Decision & Event Logging
def log_event(
    sha256: str,
    mode: str,
    event: str,
    filename: str = "",
    verdict: str = "",
    malscore: str = "N/A",
    elapsed_sec: float = 0.0,
    sent_to_sandbox: bool = False,
    info: str = ""
) -> None:
    row = [
        datetime.now(timezone.utc).isoformat(),
        f"{time.perf_counter():.6f}",
        sha256,
        filename,
        mode,
        event,
        verdict,
        malscore,
        f"{elapsed_sec:.2f}",
        sent_to_sandbox,
        info,
    ]
    with _log_lock:
        try:
            is_new = not os.path.exists(LOG_PATH)
            with open(LOG_PATH, "a", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                if is_new:
                    w.writerow([
                        "ts_utc",
                        "perf_s",
                        "sha256",
                        "filename",
                        "mode",
                        "event",
                        "verdict",
                        "malscore",
                        "elapsed_sec",
                        "sent_to_sandbox",
                        "info"
                    ])
                w.writerow(row)
        except Exception as e:
            print(f"[LOG ERROR] Failed to write log: {e}")


#Local Hash Database Lookup
def load_known_db() -> dict:
    db = {}
    if os.path.exists(KNOWN_DB):
        try:
            with open(KNOWN_DB, newline="", encoding="utf-8") as f:
                for r in csv.DictReader(f):
                    if r.get("sha256") and r.get("label"):
                        db[r["sha256"].strip().lower()] = r["label"].strip().lower()
        except Exception as e:
            print(f"[WARN] Failed to read KNOWN_DB: {e}")
    return db


KNOWN = load_known_db()


def lookup_hash(sha256: str) -> Optional[str]:
    """Return 'malicious', 'trusted', or None (unknown)."""
    return KNOWN.get(sha256.lower())


#CAPEv2 Sandbox REST API Client
def cape_headers() -> dict:
    return {"Authorization": f"Token {CAPE_TOKEN}"} if CAPE_TOKEN else {}


def cape_submit(filename: str, content: bytes) -> int:
    r = requests.post(
        f"{CAPE_URL}/apiv2/tasks/create/file/",
        headers=cape_headers(),
        files={"file": (filename, content)},
        data={"timeout": CAPE_TIMEOUT},
        timeout=60,
    )
    r.raise_for_status()
    body = r.json()
    if body.get("error"):
        raise RuntimeError(str(body))
    return body["data"]["task_ids"][0]


def cape_status(task_id: int) -> str:
    r = requests.get(
        f"{CAPE_URL}/apiv2/tasks/status/{task_id}/",
        headers=cape_headers(),
        timeout=30,
    )
    r.raise_for_status()
    return str(r.json().get("data", ""))


def cape_malscore(task_id: int) -> float:
    r = requests.get(
        f"{CAPE_URL}/apiv2/tasks/get/report/{task_id}/json/",
        headers=cape_headers(),
        timeout=60,
    )
    r.raise_for_status()
    return float(r.json().get("malscore", 0))


def verdict_from_score(score: float) -> str:
    if score >= MAL_THRESHOLD:
        return "BLOCK"
    if score <= SAFE_THRESHOLD:
        return "ALLOW"
    return "HOLD"  #Score in range 2.1 - 5.9 -> HOLD for manual review


#API Endpoints
class InspectRequest(BaseModel):
    sha256: str
    filename: Optional[str] = None
    mode: Optional[str] = None  #Override mode per request: "A" or "B"


@app.get("/health")
def health():
    return {"ok": True, "mode": DEFAULT_MODE, "known_hashes": len(KNOWN)}


@app.get("/cape-check", dependencies=[Depends(check_key)])
def cape_check():
    #Check that this backend can reach the CAPEv2 host
    url = f"{CAPE_URL}{CAPE_CHECK_PATH}"
    t0 = time.perf_counter()
    try:
        r = requests.get(url, headers=cape_headers(), timeout=15)
    except requests.RequestException as e:
        return {"reachable": False, "url": url, "error": str(e)[:200]}
    return {
        "reachable": True,
        "url": url,
        "http_status": r.status_code,
        "ok": r.ok,
        "latency_s": round(time.perf_counter() - t0, 3),
        "token_set": bool(CAPE_TOKEN),
        "body_preview": r.text[:200],
    }


@app.post("/inspect", dependencies=[Depends(check_key)])
def inspect(req: InspectRequest):
    #Step 1: Extension sends file hash. Returns decision or NEED_FILE.
    t0 = time.perf_counter()
    mode = (req.mode or DEFAULT_MODE).upper()
    h = req.sha256.lower()
    fn = req.filename or ""

    log_event(h, mode, "inspect_received", filename=fn)

    if mode == "A":
        log_event(h, mode, "decision", filename=fn, verdict="NEED_FILE", sent_to_sandbox=True, info="Mode A: sandbox all")
        return {"verdict": "NEED_FILE", "reason": "Mode A: all files forwarded to sandbox"}

    label = lookup_hash(h)
    log_event(h, mode, "hash_lookup_done", filename=fn, info=f"label={label or 'unknown'}")

    if label == "malicious":
        elapsed = time.perf_counter() - t0
        log_event(h, mode, "decision_final", filename=fn, verdict="BLOCK", malscore="10.0", elapsed_sec=elapsed, sent_to_sandbox=False, info="Known malicious hash")
        return {"verdict": "BLOCK", "reason": "known malicious"}

    if label == "trusted":
        elapsed = time.perf_counter() - t0
        log_event(h, mode, "decision_final", filename=fn, verdict="ALLOW", malscore="0.0", elapsed_sec=elapsed, sent_to_sandbox=False, info="Known trusted hash")
        return {"verdict": "ALLOW", "reason": "known trusted"}

    log_event(h, mode, "decision", filename=fn, verdict="NEED_FILE", sent_to_sandbox=True, info="Unknown hash -> sandbox")
    return {"verdict": "NEED_FILE", "reason": "unknown hash -> sandbox"}


@app.post("/submit", dependencies=[Depends(check_key)])
def submit(file: UploadFile = File(...), mode: Optional[str] = Form(None)):
    #Step 2: Upload file (if NEED_FILE) and forward it to CAPEv2 Sandbox.
    mode = (mode or DEFAULT_MODE).upper()
    content = file.file.read()
    h = _sha256(content).hexdigest()
    fn = file.filename or "sample.bin"

    log_event(h, mode, "submit_received", filename=fn, info=f"size={len(content)}B")

    try:
        task_id = cape_submit(fn, content)
    except (requests.RequestException, RuntimeError) as e:
        log_event(h, mode, "cape_submit_failed", filename=fn, verdict="RETRY", info=str(e)[:200])
        return {"verdict": "RETRY", "reason": "Unable to contact CAPEv2 Sandbox"}

    TASKS[task_id] = {
        "sha256": h,
        "mode": mode,
        "filename": fn,
        "t0": time.time(),
        "perf_t0": time.perf_counter(),
        "final": None
    }
    log_event(h, mode, "cape_submitted", filename=fn, sent_to_sandbox=True, info=f"task_id={task_id}")
    return {"verdict": "PENDING", "task_id": task_id}


@app.get("/result/{task_id}", dependencies=[Depends(check_key)])
def result(task_id: int):
    #Step 3: Extension polls for completion until verdict is non-PENDING.
    t = TASKS.get(task_id)
    if not t:
        raise HTTPException(status_code=404, detail="Task ID not found")
    if t["final"]:
        return t["final"]

    h, mode, fn = t["sha256"], t["mode"], t["filename"]
    
    try:
        status = cape_status(task_id)
    except requests.RequestException as e:
        log_event(h, mode, "cape_status_error", filename=fn, info=str(e)[:200])
        return {"verdict": "PENDING", "reason": "Failed to check status, retrying..."}

    if status == "reported":
        try:
            score = cape_malscore(task_id)
        except requests.RequestException:
            return {"verdict": "PENDING", "reason": "Report not ready yet"}
        
        v = verdict_from_score(score)
        elapsed = round(time.perf_counter() - t["perf_t0"], 2)
        final = {"verdict": v, "malscore": score}
        t["final"] = final
        
        log_event(
            sha256=h,
            mode=mode,
            event="decision_final",
            filename=fn,
            verdict=v,
            malscore=str(score),
            elapsed_sec=elapsed,
            sent_to_sandbox=True,
            info=f"CAPEv2 analysis completed with malscore {score}"
        )
        return final

    if status.startswith("failed"):
        elapsed = round(time.perf_counter() - t["perf_t0"], 2)
        final = {"verdict": "RETRY", "reason": f"CAPEv2 status: {status}"}
        t["final"] = final
        log_event(
            sha256=h,
            mode=mode,
            event="decision_final",
            filename=fn,
            verdict="RETRY",
            elapsed_sec=elapsed,
            sent_to_sandbox=True,
            info=f"Analysis failed status: {status}"
        )
        return final

    if time.time() - t["t0"] > MAX_WAIT:
        elapsed = round(time.perf_counter() - t["perf_t0"], 2)
        final = {"verdict": "HOLD", "reason": "Exceeded maximum wait time"}
        t["final"] = final
        log_event(
            sha256=h,
            mode=mode,
            event="decision_final",
            filename=fn,
            verdict="HOLD",
            elapsed_sec=elapsed,
            sent_to_sandbox=True,
            info="Exceeded MAX_WAIT threshold"
        )
        return final

    return {"verdict": "PENDING", "status": status}