import os
import re
import time
import uuid
import threading
import signal
import logging
from datetime import datetime, timezone
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from flask import Flask, jsonify, request, g
from werkzeug.exceptions import HTTPException, BadRequest

# ----------------- Configuration -----------------
CACHE_TTL = int(os.getenv("CACHE_TTL_SECONDS", str(7 * 24 * 60 * 60)))  # 7 days
SOURCES = os.getenv("SOURCES",
    ",".join([
        "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf",
        "https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.txt",
        "https://raw.githubusercontent.com/7c/fakefilter/main/txt/data.txt",
        "https://raw.githubusercontent.com/amieiro/disposable-email-domains/master/denyDomains.txt",
        "https://raw.githubusercontent.com/groundcat/disposable-email-domain-list/master/domains.txt",
    ])
).split(",")
FETCH_TIMEOUT = float(os.getenv("FETCH_TIMEOUT_SECONDS", "10"))
CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL_SECONDS", "3600"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
PORT = int(os.getenv("PORT", "5000"))

EMAIL_RE = re.compile(r"^[^@]+@[^@]+\.[^@]+$")

# ----------------- Flask app -----------------
app = Flask(__name__)

# ----------------- Logging -----------------
logger = logging.getLogger("disposable-api")
handler = logging.StreamHandler()
formatter = logging.Formatter(
    '{"time":"%(asctime)s","level":"%(levelname)s","name":"%(name)s","msg":"%(message)s"}'
)
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(LOG_LEVEL)

# ----------------- Global State -----------------
_DOMAINS = set()
_LAST_UPDATE = 0.0
_FETCH_LOCK = threading.Lock()
_SHUTDOWN_EVENT = threading.Event()

# ----------------- Requests session with retries -----------------
def make_session() -> requests.Session:
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5,
                    status_forcelist=(429, 500, 502, 503, 504),
                    allowed_methods=("GET", "HEAD"))
    session.mount("https://", HTTPAdapter(max_retries=retries))
    session.mount("http://", HTTPAdapter(max_retries=retries))
    return session

SESSION = make_session()

# ----------------- Utilities -----------------
def now_ts() -> float:
    return time.time()

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def fetch_one(url: str) -> set:
    try:
        resp = SESSION.get(url, timeout=FETCH_TIMEOUT)
        resp.raise_for_status()
        lines = {
            line.strip().lower()
            for line in resp.text.splitlines()
            if line.strip() and not line.startswith("#")
        }
        logger.info(f"Fetched {len(lines)} lines from {url}")
        return lines
    except Exception as e:
        logger.warning(f"Failed to fetch {url}: {e}")
        return set()

def fetch_all(sources: list[str]) -> set:
    merged = set()
    for url in sources:
        merged.update(fetch_one(url))
    return merged

def update_domains(force: bool = False):
    global _DOMAINS, _LAST_UPDATE
    with _FETCH_LOCK:
        age = now_ts() - _LAST_UPDATE
        if not force and _LAST_UPDATE > 0 and age < CACHE_TTL:
            logger.debug("Cache fresh, skipping update")
            return
        logger.info("Updating domain cache...")
        domains = fetch_all(SOURCES)
        if domains:
            _DOMAINS = domains
            _LAST_UPDATE = now_ts()
            logger.info(f"Domain cache updated, total={len(_DOMAINS)}")
        else:
            logger.warning("No domains fetched; keeping existing cache")

def background_updater():
    logger.info("Background updater started")
    while not _SHUTDOWN_EVENT.is_set():
        try:
            update_domains()
        except Exception as e:
            logger.exception(f"Background updater error: {e}")
        _SHUTDOWN_EVENT.wait(CHECK_INTERVAL)
    logger.info("Background updater exiting")

# ----------------- Shutdown handling -----------------
def stop_background():
    _SHUTDOWN_EVENT.set()

atexit_registered = False
try:
    import atexit
    atexit.register(stop_background)
    atexit_registered = True
except:
    pass

signal.signal(signal.SIGINT, lambda s, f: stop_background())
signal.signal(signal.SIGTERM, lambda s, f: stop_background())

# ----------------- Request middleware -----------------
@app.before_request
def inject_request_id():
    g.request_id = uuid.uuid4().hex
    g.start_ts = now_ts()

@app.after_request
def log_request(response):
    duration = now_ts() - getattr(g, "start_ts", now_ts())
    logger.info(f"req={request.method} path={request.path} id={g.request_id} "
                f"status={response.status_code} dur={duration:.3f}")
    return response

# ----------------- Error handlers -----------------
def error_response(message: str, status: int = 400, code: Optional[str] = None):
    payload = {
        "error": {"message": message, "code": code or "error"},
        "requestId": g.get("request_id"),
        "timestamp": iso_now()
    }
    response = jsonify(payload)
    response.status_code = status
    return response

@app.errorhandler(HTTPException)
def handle_http_exception(e):
    return error_response(e.description or "HTTP error", status=e.code or 500, code="http_error")

@app.errorhandler(Exception)
def handle_unexpected(e):
    logger.exception("Unhandled exception")
    return error_response("Internal server error", status=500, code="internal")

# ----------------- Helpers -----------------
def extract_email() -> Optional[str]:
    if request.method == "GET":
        return request.args.get("email")
    if request.is_json:
        data = request.get_json(silent=True) or {}
        if isinstance(data, dict):
            return data.get("email")
    return request.form.get("email")

def validate_email_syntax(email: str) -> bool:
    return bool(EMAIL_RE.match(email))

def is_domain_disposable(domain: str) -> bool:
    return domain.lower().strip() in _DOMAINS

# ----------------- Routes -----------------
@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "message": "Disposable Email Validator API running",
        "version": os.getenv("API_VERSION", "1.0.0"),
        "endpoints": {
            "validate_get": "/validate?email=you@mail.com",
            "validate_post": "/validate POST json or form 'email'",
            "health": "/health",
            "metrics": "/metrics"
        },
        "lastUpdated": datetime.fromtimestamp(_LAST_UPDATE, tz=timezone.utc).isoformat() if _LAST_UPDATE else None,
        "requestId": g.request_id
    })

@app.route("/validate", methods=["GET", "POST"])
def validate():
    email = extract_email()
    if not email:
        raise BadRequest("email parameter missing")
    if "@" not in email or not validate_email_syntax(email):
        raise BadRequest("invalid email format")
    domain = email.split("@")[-1].lower().strip()
    disposable = is_domain_disposable(domain)
    return jsonify({
        "email": email,
        "domain": domain,
        "isDisposable": disposable,
        "lastUpdated": datetime.fromtimestamp(_LAST_UPDATE, tz=timezone.utc).isoformat() if _LAST_UPDATE else None,
        "requestId": g.request_id
    })

@app.route("/health", methods=["GET"])
def health():
    age = now_ts() - _LAST_UPDATE if _LAST_UPDATE else None
    status = "ok" if _LAST_UPDATE and age < (CACHE_TTL*2) else "warn"
    return jsonify({
        "status": status,
        "domainsCached": len(_DOMAINS),
        "lastUpdatedSecondsAgo": int(age) if age else None,
        "timestamp": iso_now(),
        "requestId": g.request_id
    })

@app.route("/metrics", methods=["GET"])
def metrics():
    return jsonify({
        "domainsCached": len(_DOMAINS),
        "lastUpdatedEpoch": int(_LAST_UPDATE) if _LAST_UPDATE else None,
        "timestamp": iso_now(),
        "requestId": g.request_id
    })

# ----------------- Start background updater -----------------
updater_thread = threading.Thread(target=background_updater, daemon=True)
update_domains(force=True)  # initial fetch
updater_thread.start()

# ----------------- Run Flask -----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
