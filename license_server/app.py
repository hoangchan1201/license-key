"""DewTool license API. Deploy as a Render web service with PostgreSQL."""
from __future__ import annotations

import hashlib
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone

import psycopg
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, jsonify, request
from psycopg.rows import dict_row

app = Flask(__name__)
DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_TOKEN = os.environ.get("LICENSE_ADMIN_TOKEN", "")
LICENSE_KEY_ENCRYPTION_KEY = os.environ.get("LICENSE_KEY_ENCRYPTION_KEY", "")
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
                encrypted_key TEXT,
                duration_seconds BIGINT NOT NULL CHECK (duration_seconds > 0),
                issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                activated_at TIMESTAMPTZ,
                expires_at TIMESTAMPTZ,
                machine_id TEXT,
                username TEXT,
                online_since TIMESTAMPTZ,
                last_seen TIMESTAMPTZ,
                revoked_at TIMESTAMPTZ
            )
        """)
        # Existing installations only have hashes; the new nullable column lets
        # future keys be recoverable by the authenticated admin API.
        conn.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS encrypted_key TEXT")
        conn.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS username TEXT")
        conn.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS online_since TIMESTAMPTZ")
        conn.execute("UPDATE licenses SET online_since=last_seen WHERE online_since IS NULL AND last_seen IS NOT NULL")


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
    username = str(data.get("username", "")).strip()[:80]
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
        new_online_session = not row["last_seen"] or (now - row["last_seen"]).total_seconds() > ONLINE_WINDOW_SECONDS
        if not row["activated_at"]:
            conn.execute(
                "UPDATE licenses SET activated_at=%s, expires_at=%s, machine_id=%s, last_seen=%s, online_since=%s, username=%s WHERE key_hash=%s",
                (now, now + timedelta(seconds=row["duration_seconds"]), machine_id, now, now, username or None, row["key_hash"]),
            )
            row["activated_at"] = now
            row["expires_at"] = now + timedelta(seconds=row["duration_seconds"])
            row["machine_id"] = machine_id
        elif row["expires_at"] <= now:
            return None, (jsonify(valid=False, error="expired", expires_at=row["expires_at"].isoformat()), 403)
        if username:
            conn.execute("UPDATE licenses SET last_seen=%s, online_since=CASE WHEN %s THEN %s ELSE online_since END, username=%s WHERE key_hash=%s",
                         (now, new_online_session, now, username, row["key_hash"]))
            row["username"] = username
        else:
            conn.execute("UPDATE licenses SET last_seen=%s, online_since=CASE WHEN %s THEN %s ELSE online_since END WHERE key_hash=%s",
                         (now, new_online_session, now, row["key_hash"]))
        if new_online_session:
            row["online_since"] = now
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


@app.post("/api/v1/offline")
def client_offline():
    data = get_payload()
    key = str(data.get("key", "")).strip().upper()
    machine_id = str(data.get("machine_id", "")).strip()
    if not key or not machine_id:
        return jsonify(error="invalid_request"), 400
    with db() as conn:
        result = conn.execute(
            "UPDATE licenses SET last_seen=NULL, online_since=NULL WHERE key_hash=%s AND machine_id=%s",
            (key_hash(key), machine_id),
        )
        if result.rowcount == 0:
            return jsonify(error="license_or_machine_not_found"), 404
    return jsonify(offline=True)


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
    if not LICENSE_KEY_ENCRYPTION_KEY:
        return jsonify(error="key_encryption_not_configured"), 503
    try:
        key_cipher = Fernet(LICENSE_KEY_ENCRYPTION_KEY.encode("ascii"))
    except Exception:
        app.logger.exception("LICENSE_KEY_ENCRYPTION_KEY is invalid")
        return jsonify(error="key_encryption_configuration_invalid"), 503
    data = get_payload()
    try:
        # Accept duration_seconds for hourly keys; retain days for older admin clients.
        if "duration_seconds" in data:
            duration_seconds = int(data.get("duration_seconds", 0))
        else:
            duration_seconds = int(data.get("days", 0)) * 86400
        count = max(1, min(100, int(data.get("count", 1))))
        if duration_seconds < 3600:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify(error="duration_must_be_at_least_1_hour; count_1_to_100"), 400
    max_seconds = int((datetime.max.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).total_seconds())
    if duration_seconds > max_seconds:
        return jsonify(error="duration_exceeds_supported_calendar_range"), 400

    generated = []
    with db() as conn:
        for _ in range(count):
            key = "DEW-" + "-".join(secrets.token_hex(3).upper() for _ in range(3))
            conn.execute(
                "INSERT INTO licenses(key_hash,key_hint,encrypted_key,duration_seconds) VALUES (%s,%s,%s,%s)",
                (key_hash(key), key[:8] + "…" + key[-4:], key_cipher.encrypt(key.encode("utf-8")).decode("ascii"), duration_seconds),
            )
            generated.append(key)
    return jsonify(created=len(generated), duration_seconds=duration_seconds, keys=generated), 201


@app.get("/api/v1/admin/licenses")
def list_licenses():
    denied = require_admin()
    if denied:
        return denied
    now = datetime.now(timezone.utc)
    with db() as conn:
        rows = conn.execute(
            "SELECT key_hash, key_hint, encrypted_key, duration_seconds, issued_at, activated_at, expires_at, last_seen, online_since, revoked_at, username FROM licenses ORDER BY issued_at DESC"
        ).fetchall()
    try:
        key_cipher = Fernet(LICENSE_KEY_ENCRYPTION_KEY.encode("ascii")) if LICENSE_KEY_ENCRYPTION_KEY else None
    except Exception:
        key_cipher = None
    output = []
    for row in rows:
        online = bool(row["last_seen"] and (now - row["last_seen"]).total_seconds() <= ONLINE_WINDOW_SECONDS and not row["revoked_at"] and (not row["expires_at"] or row["expires_at"] > now))
        online_seconds = max(0, int((now - row["online_since"]).total_seconds())) if online and row["online_since"] else 0
        full_key = None
        if row["encrypted_key"] and key_cipher:
            try:
                full_key = key_cipher.decrypt(row["encrypted_key"].encode("ascii")).decode("utf-8")
            except (InvalidToken, ValueError, UnicodeError):
                full_key = None
        output.append({
            "license_id": row["key_hash"], "key_hint": row["key_hint"], "key": full_key,
            "username": row["username"],
            "online_seconds": online_seconds,
            "duration_seconds": row["duration_seconds"], "activated_at": row["activated_at"],
            "expires_at": row["expires_at"], "online": online,
            "revoked": bool(row["revoked_at"]),
        })
    return jsonify(licenses=output, online_window_seconds=ONLINE_WINDOW_SECONDS)


def _admin_license_id():
    data = get_payload()
    license_id = str(data.get("license_id", "")).strip().lower()
    if len(license_id) == 64 and all(char in "0123456789abcdef" for char in license_id):
        return license_id
    key = str(data.get("key", "")).strip().upper()
    if key:
        return key_hash(key)
    key_hint = str(data.get("key_hint", "")).strip()
    if key_hint:
        with db() as conn:
            row = conn.execute("SELECT key_hash FROM licenses WHERE key_hint=%s ORDER BY issued_at DESC LIMIT 1", (key_hint,)).fetchone()
        return row["key_hash"] if row else ""
    return ""


@app.post("/api/v1/admin/revoke")
def revoke_license():
    denied = require_admin()
    if denied:
        return denied
    license_id = _admin_license_id()
    if not license_id:
        return jsonify(error="key_required"), 400
    with db() as conn:
        result = conn.execute("UPDATE licenses SET revoked_at=now() WHERE key_hash=%s", (license_id,))
        if result.rowcount == 0:
            return jsonify(error="not_found"), 404
    return jsonify(revoked=True)


@app.post("/api/v1/admin/reset")
def reset_license():
    denied = require_admin()
    if denied:
        return denied
    license_id = _admin_license_id()
    if not license_id:
        return jsonify(error="key_required"), 400
    with db() as conn:
        result = conn.execute(
            "UPDATE licenses SET activated_at=NULL, expires_at=NULL, machine_id=NULL, online_since=NULL, last_seen=NULL, revoked_at=NULL WHERE key_hash=%s",
            (license_id,),
        )
        if result.rowcount == 0:
            return jsonify(error="not_found"), 404
    return jsonify(reset=True)


@app.post("/api/v1/admin/delete")
def delete_license():
    denied = require_admin()
    if denied:
        return denied
    license_id = _admin_license_id()
    if not license_id:
        return jsonify(error="key_required"), 400
    with db() as conn:
        result = conn.execute("DELETE FROM licenses WHERE key_hash=%s", (license_id,))
        if result.rowcount == 0:
            return jsonify(error="not_found"), 404
    return jsonify(deleted=True)


@app.post("/api/v1/admin/rename")
def rename_license():
    denied = require_admin()
    if denied:
        return denied
    data = get_payload()
    license_id = _admin_license_id()
    username = str(data.get("username", "")).strip()
    if not license_id:
        return jsonify(error="key_required"), 400
    if not username or len(username) > 80:
        return jsonify(error="username_required_max_80_chars"), 400
    with db() as conn:
        result = conn.execute("UPDATE licenses SET username=%s WHERE key_hash=%s", (username, license_id))
        if result.rowcount == 0:
            return jsonify(error="not_found"), 404
    return jsonify(updated=True, username=username)


@app.post("/api/v1/admin/extend")
def extend_license():
    denied = require_admin()
    if denied:
        return denied
    data = get_payload()
    license_id = _admin_license_id()
    try:
        added_seconds = int(data.get("duration_seconds", 0))
    except (TypeError, ValueError):
        return jsonify(error="duration_must_be_at_least_1_hour"), 400
    if not license_id:
        return jsonify(error="key_required"), 400
    if added_seconds < 3600:
        return jsonify(error="duration_must_be_at_least_1_hour"), 400

    now = datetime.now(timezone.utc)
    max_seconds = int((datetime.max.replace(tzinfo=timezone.utc) - now).total_seconds())
    if added_seconds > max_seconds:
        return jsonify(error="duration_exceeds_supported_calendar_range"), 400
    with db() as conn:
        row = conn.execute(
            "SELECT duration_seconds, activated_at, expires_at, revoked_at FROM licenses WHERE key_hash=%s FOR UPDATE",
            (license_id,),
        ).fetchone()
        if not row:
            return jsonify(error="not_found"), 404
        if row["revoked_at"]:
            return jsonify(error="license_revoked"), 409
        total_seconds = int(row["duration_seconds"]) + added_seconds
        if row["expires_at"] is None:
            conn.execute("UPDATE licenses SET duration_seconds=%s WHERE key_hash=%s", (total_seconds, license_id))
            expires_at = None
        else:
            base_expiry = max(row["expires_at"], now)
            if added_seconds > int((datetime.max.replace(tzinfo=timezone.utc) - base_expiry).total_seconds()):
                return jsonify(error="duration_exceeds_supported_calendar_range"), 400
            expires_at = base_expiry + timedelta(seconds=added_seconds)
            activated_at = row["activated_at"] or now
            conn.execute(
                "UPDATE licenses SET duration_seconds=%s, activated_at=%s, expires_at=%s WHERE key_hash=%s",
                (total_seconds, activated_at, expires_at, license_id),
            )
    return jsonify(extended=True, added_seconds=added_seconds, duration_seconds=total_seconds,
                   expires_at=expires_at.isoformat() if expires_at else None)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
