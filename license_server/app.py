"""DewTool license API. Deploy as a Render web service with PostgreSQL."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone

import psycopg
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flask import Flask, jsonify, request
from psycopg.rows import dict_row

app = Flask(__name__)
DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_TOKEN = os.environ.get("LICENSE_ADMIN_TOKEN", "")
LICENSE_KEY_ENCRYPTION_KEY = os.environ.get("LICENSE_KEY_ENCRYPTION_KEY", "")
OFFLINE_SIGNING_PRIVATE_KEY = os.environ.get("OFFLINE_SIGNING_PRIVATE_KEY", "")
OFFLINE_PUBLIC_KEY_B64 = "pZGxOrhEV2ZQsADbhnKXqSrh-HEwX52FJlmNoETj17k"
ONLINE_WINDOW_SECONDS = 100
MINIMUM_CLIENT_VERSION = os.environ.get("MINIMUM_CLIENT_VERSION", "1.0.25").strip().lstrip("vV")
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
                offline_at TIMESTAMPTZ,
                revoked_at TIMESTAMPTZ
            )
        """)
        # Existing installations only have hashes; the new nullable column lets
        # future keys be recoverable by the authenticated admin API.
        conn.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS encrypted_key TEXT")
        conn.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS username TEXT")
        conn.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS is_free BOOLEAN NOT NULL DEFAULT FALSE")
        conn.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS online_since TIMESTAMPTZ")
        conn.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS offline_at TIMESTAMPTZ")
        conn.execute("UPDATE licenses SET online_since=last_seen WHERE online_since IS NULL AND last_seen IS NOT NULL")
@app.before_request
def ensure_schema():
    # Free offline keys are signed statelessly and intentionally work even
    # when Neon is unavailable or has reached its monthly compute quota.
    if request.path == "/api/v1/offline-free-key":
        return
    # Retry initialization when the free database has just resumed from idle.
    global _SCHEMA_READY
    if not _SCHEMA_READY:
        with _SCHEMA_LOCK:
            if not _SCHEMA_READY:
                init_db()
                _SCHEMA_READY = True


@app.errorhandler(psycopg.errors.QueryCanceled)
@app.errorhandler(psycopg.errors.LockNotAvailable)
def database_request_timeout(_error):
    app.logger.warning("License API request stopped by database timeout")
    return jsonify(error="server_busy"), 503


def key_hash(key: str) -> str:
    return hashlib.sha256(key.strip().upper().encode("utf-8")).hexdigest()


def get_payload():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _urlsafe_b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _offline_signer() -> Ed25519PrivateKey | None:
    """Load the owner-only signing key from Render environment variables."""
    try:
        encoded = str(OFFLINE_SIGNING_PRIVATE_KEY or "").strip()
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        if len(raw) != 32:
            return None
        signer = Ed25519PrivateKey.from_private_bytes(raw)
        public = _urlsafe_b64(signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ))
        return signer if public == OFFLINE_PUBLIC_KEY_B64 else None
    except Exception:
        return None


@app.post("/api/v1/offline-free-key")
def issue_offline_free_key():
    """Issue a 24-hour device-bound key without opening a database connection."""
    machine_id = str(get_payload().get("machine_id") or "").strip()
    if not machine_id or len(machine_id) > 128:
        return jsonify(error="invalid_request"), 400
    signer = _offline_signer()
    if signer is None:
        app.logger.error("OFFLINE_FREE_KEY_UNAVAILABLE signer is missing or mismatched")
        return jsonify(error="offline_signer_not_configured"), 503
    now = int(time.time())
    expires_at = now + 86400
    key_id = secrets.token_urlsafe(12)
    payload = {"v": 1, "id": key_id, "exp": expires_at, "mid": machine_id, "kind": "free"}
    encoded_payload = _urlsafe_b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = _urlsafe_b64(signer.sign(encoded_payload.encode("ascii")))
    # Render logs are the intentional temporary issuance history. Do not log
    # the usable key itself, only its id and a non-reversible device hash.
    device_hint = hashlib.sha256(machine_id.encode("utf-8")).hexdigest()[:12]
    app.logger.info("OFFLINE_FREE_KEY_ISSUED id=%s device=%s expires_at=%s", key_id, device_hint, datetime.fromtimestamp(expires_at, timezone.utc).isoformat())
    return jsonify(key=f"DEW-O1.{encoded_payload}.{signature}", expires_at=datetime.fromtimestamp(expires_at, timezone.utc).isoformat(), seconds_left=86400)


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
        "username": row.get("username"),
    }


@app.get("/health")
def health():
    # A health check must not wake or consume the serverless database.
    return jsonify(ok=True, service="DewTool License API")


def verify_client_request():
    client_version = str(request.headers.get("X-Client-Version", "")).strip().lstrip("vV")
    if not _client_version_is_supported(client_version):
        return None, (jsonify(
            valid=False,
            error="update_required",
            minimum_version=MINIMUM_CLIENT_VERSION,
            message=f"Please update DewTool to version {MINIMUM_CLIENT_VERSION} or newer.",
        ), 426)

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
        if not row["activated_at"]:
            if not username:
                return None, (jsonify(valid=False, error="username_required"), 400)
            conn.execute(
                "UPDATE licenses SET activated_at=%s, expires_at=%s, machine_id=%s, last_seen=%s, online_since=%s, offline_at=NULL, username=%s WHERE key_hash=%s",
                (now, now + timedelta(seconds=row["duration_seconds"]), machine_id, now, now, username or None, row["key_hash"]),
            )
            row["activated_at"] = now
            row["expires_at"] = now + timedelta(seconds=row["duration_seconds"])
            row["machine_id"] = machine_id
            row["username"] = username
        elif row["expires_at"] <= now:
            return None, (jsonify(valid=False, error="expired", expires_at=row["expires_at"].isoformat()), 403)
        # Only record a single ON marker when the tool explicitly verifies
        # its key. Periodic heartbeats are intentionally not used.
        conn.execute("UPDATE licenses SET last_seen=%s, online_since=%s, offline_at=NULL WHERE key_hash=%s",
                     (now, now, row["key_hash"]))
        row["online_since"] = now
        row["last_seen"] = now
        return license_result(row, now), None


def _client_version_is_supported(version):
    """Reject clients that omit a version or are below the configured floor."""
    import re

    def parts(value):
        found = re.findall(r"\d+", str(value or ""))
        return tuple(int(item) for item in found) if found else ()

    current = parts(version)
    minimum = parts(MINIMUM_CLIENT_VERSION)
    if not current or not minimum:
        return False
    width = max(len(current), len(minimum))
    return current + (0,) * (width - len(current)) >= minimum + (0,) * (width - len(minimum))


@app.post("/api/v1/activate")
def activate():
    result, error = verify_client_request()
    return error if error else jsonify(result)


@app.post("/api/v1/username")
def update_client_username():
    data = get_payload()
    key = str(data.get("key", "")).strip().upper()
    machine_id = str(data.get("machine_id", "")).strip()
    username = str(data.get("username", "")).strip()
    if not key or len(key) > 100 or not machine_id or len(machine_id) > 128:
        return jsonify(updated=False, error="invalid_request"), 400
    if not username or len(username) > 80:
        return jsonify(updated=False, error="username_required_max_80_chars"), 400
    now = datetime.now(timezone.utc)
    with db() as conn:
        row = conn.execute(
            "SELECT machine_id, activated_at, expires_at, revoked_at FROM licenses WHERE key_hash=%s FOR UPDATE",
            (key_hash(key),),
        ).fetchone()
        if not row:
            return jsonify(updated=False, error="invalid_key"), 404
        if row["revoked_at"]:
            return jsonify(updated=False, error="revoked"), 403
        if not row["activated_at"]:
            return jsonify(updated=False, error="not_activated"), 409
        if row["machine_id"] != machine_id:
            return jsonify(updated=False, error="bound_to_another_device"), 409
        if row["expires_at"] and row["expires_at"] <= now:
            return jsonify(updated=False, error="expired"), 403
        conn.execute("UPDATE licenses SET username=%s WHERE key_hash=%s", (username, key_hash(key)))
    return jsonify(updated=True, username=username)


@app.post("/api/v1/offline")
def client_offline():
    data = get_payload()
    key = str(data.get("key", "")).strip().upper()
    machine_id = str(data.get("machine_id", "")).strip()
    if not key or not machine_id:
        return jsonify(error="invalid_request"), 400
    with db() as conn:
        result = conn.execute(
            "UPDATE licenses SET offline_at=%s, last_seen=NULL, online_since=NULL WHERE key_hash=%s AND machine_id=%s",
            (datetime.now(timezone.utc), key_hash(key), machine_id),
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
                "INSERT INTO licenses(key_hash,key_hint,encrypted_key,duration_seconds,is_free) VALUES (%s,%s,%s,%s,%s)",
                (key_hash(key), key[:8] + "…" + key[-4:], key_cipher.encrypt(key.encode("utf-8")).decode("ascii"), duration_seconds, False),
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
            "SELECT key_hash, key_hint, encrypted_key, duration_seconds, issued_at, activated_at, expires_at, last_seen, online_since, offline_at, revoked_at, username FROM licenses WHERE COALESCE(is_free,FALSE)=FALSE ORDER BY issued_at DESC"
        ).fetchall()
    try:
        key_cipher = Fernet(LICENSE_KEY_ENCRYPTION_KEY.encode("ascii")) if LICENSE_KEY_ENCRYPTION_KEY else None
    except Exception:
        key_cipher = None
    output = []
    for row in rows:
        # ON stays visible from the explicit verification until a normal tool
        # close writes OFF. A forced close cannot be detected without a
        # recurring heartbeat, by design.
        online = bool(row["online_since"] and not row["offline_at"] and not row["revoked_at"] and (not row["expires_at"] or row["expires_at"] > now))
        offline_at = row["offline_at"]
        full_key = None
        if row["encrypted_key"] and key_cipher:
            try:
                full_key = key_cipher.decrypt(row["encrypted_key"].encode("ascii")).decode("utf-8")
            except (InvalidToken, ValueError, UnicodeError):
                full_key = None
        output.append({
            "license_id": row["key_hash"], "key_hint": row["key_hint"], "key": full_key,
            "username": row["username"],
            "online_since": row["online_since"],
            "offline_at": offline_at,
            "duration_seconds": row["duration_seconds"], "activated_at": row["activated_at"],
            "expires_at": row["expires_at"], "online": online,
            "revoked": bool(row["revoked_at"]),
        })
    return jsonify(licenses=output)


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
        result = conn.execute("UPDATE licenses SET revoked_at=now(), offline_at=now(), last_seen=NULL, online_since=NULL WHERE key_hash=%s", (license_id,))
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
            "UPDATE licenses SET activated_at=NULL, expires_at=NULL, machine_id=NULL, online_since=NULL, last_seen=NULL, offline_at=NULL, revoked_at=NULL WHERE key_hash=%s",
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


@app.post("/api/v1/admin/reduce")
def reduce_licenses():
    """Subtract one duration from one or more licenses atomically."""
    denied = require_admin()
    if denied:
        return denied
    data = get_payload()
    try:
        reduce_seconds = int(data.get("duration_seconds", 0))
    except (TypeError, ValueError):
        return jsonify(error="duration_must_be_at_least_1_hour"), 400
    if reduce_seconds < 3600:
        return jsonify(error="duration_must_be_at_least_1_hour"), 400

    raw_ids = data.get("license_ids")
    if raw_ids is None:
        single_id = _admin_license_id()
        raw_ids = [single_id] if single_id else []
    if not isinstance(raw_ids, list) or not raw_ids or len(raw_ids) > 100:
        return jsonify(error="license_ids_required_max_100"), 400
    license_ids = []
    for value in raw_ids:
        license_id = str(value or "").strip().lower()
        if len(license_id) != 64 or any(char not in "0123456789abcdef" for char in license_id):
            return jsonify(error="invalid_license_id"), 400
        if license_id not in license_ids:
            license_ids.append(license_id)

    now = datetime.now(timezone.utc)
    with db() as conn:
        records = []
        # Validate the whole batch before writing anything so an invalid or
        # too-short key cannot leave the rest of the selection partially changed.
        for license_id in license_ids:
            row = conn.execute(
                "SELECT duration_seconds, expires_at, revoked_at FROM licenses WHERE key_hash=%s FOR UPDATE",
                (license_id,),
            ).fetchone()
            if not row:
                return jsonify(error="not_found", license_id=license_id), 404
            if row["revoked_at"]:
                return jsonify(error="license_revoked", license_id=license_id), 409
            current_duration = int(row["duration_seconds"])
            if current_duration - reduce_seconds < 3600:
                return jsonify(error="reduction_would_leave_less_than_1_hour",
                               license_id=license_id), 400
            records.append((license_id, row, current_duration - reduce_seconds))

        results = []
        for license_id, row, new_duration in records:
            expires_at = row["expires_at"]
            if expires_at is not None:
                expires_at = max(now, expires_at - timedelta(seconds=reduce_seconds))
                conn.execute(
                    "UPDATE licenses SET duration_seconds=%s, expires_at=%s, "
                    "offline_at=CASE WHEN %s <= %s THEN COALESCE(offline_at, %s) ELSE offline_at END, "
                    "last_seen=CASE WHEN %s <= %s THEN NULL ELSE last_seen END, "
                    "online_since=CASE WHEN %s <= %s THEN NULL ELSE online_since END "
                    "WHERE key_hash=%s",
                    (new_duration, expires_at, expires_at, now, now,
                     expires_at, now, expires_at, now, license_id),
                )
            else:
                conn.execute(
                    "UPDATE licenses SET duration_seconds=%s WHERE key_hash=%s",
                    (new_duration, license_id),
                )
            results.append({
                "license_id": license_id,
                "duration_seconds": new_duration,
                "expires_at": expires_at.isoformat() if expires_at else None,
            })
    return jsonify(reduced=len(results), reduced_seconds=reduce_seconds, licenses=results)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
