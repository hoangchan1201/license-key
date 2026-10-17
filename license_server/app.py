"""DewTool license API. Deploy as a Render web service with PostgreSQL."""
from __future__ import annotations

import hashlib
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone

import psycopg
from flask import Flask, jsonify, request
from psycopg.rows import dict_row

app = Flask(__name__)
DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_TOKEN = os.environ.get("LICENSE_ADMIN_TOKEN", "")
ONLINE_WINDOW_SECONDS = 100
_SCHEMA_READY = False
_SCHEMA_LOCK = threading.Lock()


def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")
    return psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=12)


def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                key_hash TEXT PRIMARY KEY,
                key_hint TEXT NOT NULL,
                duration_seconds BIGINT NOT NULL CHECK (duration_seconds > 0),
                issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                activated_at TIMESTAMPTZ,
                expires_at TIMESTAMPTZ,
                machine_id TEXT,
                last_seen TIMESTAMPTZ,
                revoked_at TIMESTAMPTZ
            )
        """)


@app.before_request
def ensure_schema():
    # Retry initialization when the free database has just resumed from idle.
    global _SCHEMA_READY
    if not _SCHEMA_READY:
        with _SCHEMA_LOCK:
            if not _SCHEMA_READY:
                init_db()
                _SCHEMA_READY = True


def key_hash(key: str) -> str:
    return hashlib.sha256(key.strip().upper().encode("utf-8")).hexdigest()


def get_payload():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def license_result(row, now=None):
    now = now or datetime.now(timezone.utc)
    expires = row["expires_at"]
    remaining = max(0, int((expires - now).total_seconds())) if expires else None
    return {
        "valid": True,
        "activated": expires is not None,
        "expires_at": expires.isoformat() if expires else None,
        "seconds_left": remaining,
        "server_time": now.isoformat(),
    }


@app.get("/health")
def health():
    try:
        with db() as conn:
            conn.execute("SELECT 1")
        return jsonify(ok=True, service="DewTool License API")
    except Exception:
        app.logger.exception("health check failed")
        return jsonify(ok=False), 503


def verify_client_request(heartbeat=False):
    data = get_payload()
    key = str(data.get("key", "")).strip().upper()
    machine_id = str(data.get("machine_id", "")).strip()
    if not key or len(key) > 100 or not machine_id or len(machine_id) > 128:
        return None, (jsonify(valid=False, error="invalid_request"), 400)

    now = datetime.now(timezone.utc)
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM licenses WHERE key_hash=%s FOR UPDATE", (key_hash(key),)
        ).fetchone()
        if not row:
            return None, (jsonify(valid=False, error="invalid_key"), 404)
        if row["revoked_at"]:
            return None, (jsonify(valid=False, error="revoked"), 403)
        if row["machine_id"] and row["machine_id"] != machine_id:
            return None, (jsonify(valid=False, error="bound_to_another_device"), 409)
        if not row["activated_at"]:
            conn.execute(
                "UPDATE licenses SET activated_at=%s, expires_at=%s, machine_id=%s, last_seen=%s WHERE key_hash=%s",
                (now, now + timedelta(seconds=row["duration_seconds"]), machine_id, now, row["key_hash"]),
            )
            row["activated_at"] = now
            row["expires_at"] = now + timedelta(seconds=row["duration_seconds"])
            row["machine_id"] = machine_id
        elif row["expires_at"] <= now:
            return None, (jsonify(valid=False, error="expired", expires_at=row["expires_at"].isoformat()), 403)
        conn.execute("UPDATE licenses SET last_seen=%s WHERE key_hash=%s", (now, row["key_hash"]))
        row["last_seen"] = now
        return license_result(row, now), None


@app.post("/api/v1/activate")
def activate():
    result, error = verify_client_request()
    return error if error else jsonify(result)


@app.post("/api/v1/heartbeat")
def heartbeat():
    result, error = verify_client_request(heartbeat=True)
    return error if error else jsonify(result)


def require_admin():
    if not ADMIN_TOKEN or not secrets.compare_digest(
        request.headers.get("Authorization", ""), f"Bearer {ADMIN_TOKEN}"
    ):
        return jsonify(error="unauthorized"), 401
    return None


@app.post("/api/v1/admin/licenses")
def create_licenses():
    denied = require_admin()
    if denied:
        return denied
    data = get_payload()
    try:
        days = int(data.get("days", 0))
        count = max(1, min(100, int(data.get("count", 1))))
        if not 1 <= days <= 3650:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify(error="days_must_be_1_to_3650; count_1_to_100"), 400

    generated = []
    with db() as conn:
        for _ in range(count):
            key = "DEW-" + "-".join(secrets.token_hex(3).upper() for _ in range(3))
            conn.execute(
                "INSERT INTO licenses(key_hash,key_hint,duration_seconds) VALUES (%s,%s,%s)",
                (key_hash(key), key[:8] + "…" + key[-4:], days * 86400),
            )
            generated.append(key)
    return jsonify(created=len(generated), days=days, keys=generated), 201


@app.get("/api/v1/admin/licenses")
def list_licenses():
    denied = require_admin()
    if denied:
        return denied
    now = datetime.now(timezone.utc)
    with db() as conn:
        rows = conn.execute(
            "SELECT key_hint, issued_at, activated_at, expires_at, last_seen, revoked_at FROM licenses ORDER BY issued_at DESC"
        ).fetchall()
    output = []
    for row in rows:
        online = bool(row["last_seen"] and (now - row["last_seen"]).total_seconds() <= ONLINE_WINDOW_SECONDS and not row["revoked_at"] and (not row["expires_at"] or row["expires_at"] > now))
        output.append({
            "key_hint": row["key_hint"], "activated_at": row["activated_at"],
            "expires_at": row["expires_at"], "online": online,
            "revoked": bool(row["revoked_at"]),
        })
    return jsonify(licenses=output, online_window_seconds=ONLINE_WINDOW_SECONDS)


@app.post("/api/v1/admin/revoke")
def revoke_license():
    denied = require_admin()
    if denied:
        return denied
    key = str(get_payload().get("key", "")).strip().upper()
    if not key:
        return jsonify(error="key_required"), 400
    with db() as conn:
        result = conn.execute("UPDATE licenses SET revoked_at=now() WHERE key_hash=%s", (key_hash(key),))
        if result.rowcount == 0:
            return jsonify(error="not_found"), 404
    return jsonify(revoked=True)


@app.post("/api/v1/admin/reset")
def reset_license():
    denied = require_admin()
    if denied:
        return denied
    key = str(get_payload().get("key", "")).strip().upper()
    if not key:
        return jsonify(error="key_required"), 400
    with db() as conn:
        result = conn.execute(
            "UPDATE licenses SET activated_at=NULL, expires_at=NULL, machine_id=NULL, last_seen=NULL, revoked_at=NULL WHERE key_hash=%s",
            (key_hash(key),),
        )
        if result.rowcount == 0:
            return jsonify(error="not_found"), 404
    return jsonify(reset=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
