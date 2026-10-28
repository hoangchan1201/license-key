"""DewTool license API. Deploy as a Render web service with PostgreSQL."""
from __future__ import annotations

import hashlib
import hmac
import base64
import io
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone

import psycopg
from PIL import Image, ImageDraw, ImageFont
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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS free_key_captchas (
                challenge_id TEXT PRIMARY KEY,
                machine_id TEXT NOT NULL,
                answer_hash TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                used_at TIMESTAMPTZ
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
        "username": row.get("username"),
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
        conn.execute("UPDATE licenses SET last_seen=%s, online_since=CASE WHEN %s THEN %s ELSE online_since END, offline_at=CASE WHEN %s THEN NULL ELSE offline_at END WHERE key_hash=%s",
                     (now, new_online_session, now, new_online_session, row["key_hash"]))
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
            "UPDATE licenses SET offline_at=CASE WHEN last_seen IS NOT NULL THEN LEAST(%s, last_seen + (%s * INTERVAL '1 second')) ELSE offline_at END, last_seen=NULL, online_since=NULL WHERE key_hash=%s AND machine_id=%s",
            (datetime.now(timezone.utc), ONLINE_WINDOW_SECONDS, key_hash(key), machine_id),
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
                (key_hash(key), key[:8] + "…" + key[-4:], key_cipher.encrypt(key.encode("utf-8")).decode("ascii"), duration_seconds, bool(data.get("free", False))),
            )
            generated.append(key)
    return jsonify(created=len(generated), duration_seconds=duration_seconds, keys=generated), 201


@app.post("/api/v1/free-key/captcha")
def issue_free_key_captcha():
    """Issue a short-lived image CAPTCHA challenge for a free-key claim."""
    data = get_payload()
    machine_id = str(data.get("machine_id", "")).strip()
    if not machine_id or len(machine_id) > 128:
        return jsonify(error="invalid_request"), 400
    with db() as conn:
        recent = conn.execute(
            "SELECT COUNT(*) AS n FROM free_key_captchas "
            "WHERE machine_id=%s AND expires_at > now() - INTERVAL '10 minutes'",
            (machine_id,),
        ).fetchone()["n"]
        if recent >= 8:
            return jsonify(error="captcha_rate_limited"), 429
        # Keep the challenge table small without requiring an external scheduler.
        conn.execute("DELETE FROM free_key_captchas WHERE expires_at < now() - INTERVAL '1 day'")
        challenge_id = secrets.token_urlsafe(24)
        alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
        answer = "".join(secrets.choice(alphabet) for _ in range(5))
        answer_hash = hashlib.sha256(f"{challenge_id}:{machine_id}:{answer}".encode("utf-8")).hexdigest()
        conn.execute(
            "INSERT INTO free_key_captchas(challenge_id,machine_id,answer_hash,expires_at) "
            "VALUES (%s,%s,%s,now() + INTERVAL '5 minutes')",
            (challenge_id, machine_id, answer_hash),
        )
    image = Image.new("RGB", (190, 62), (242, 244, 247))
    draw = ImageDraw.Draw(image)
    try:
        font = ImageFont.truetype("DejaVuSans.ttf", 34)
    except Exception:
        try:
            font = ImageFont.load_default(size=34)
        except TypeError:
            font = ImageFont.load_default()
    for _ in range(7):
        draw.line(
            (secrets.randbelow(190), secrets.randbelow(62), secrets.randbelow(190), secrets.randbelow(62)),
            fill=(secrets.randbelow(150), secrets.randbelow(150), secrets.randbelow(150)), width=1,
        )
    x = 12
    for char in answer:
        y = secrets.randbelow(12) + 7
        draw.text((x, y), char, font=font,
                  fill=(secrets.randbelow(90), secrets.randbelow(90), secrets.randbelow(90)))
        x += 34
    output = io.BytesIO()
    image.save(output, format="PNG")
    captcha_image = base64.b64encode(output.getvalue()).decode("ascii")
    return jsonify(challenge_id=challenge_id, image=captcha_image, expires_in=300)


@app.post("/api/v1/free-key")
def claim_free_key():
    """Reserve one unused free key after consuming a valid server CAPTCHA."""
    data = get_payload()
    machine_id = str(data.get("machine_id", "")).strip()
    challenge_id = str(data.get("challenge_id", "")).strip()
    answer = str(data.get("captcha_answer", "")).strip().upper()
    if (not machine_id or len(machine_id) > 128 or not challenge_id
            or len(challenge_id) > 128 or not answer or len(answer) > 8):
        return jsonify(error="invalid_request"), 400
    if not LICENSE_KEY_ENCRYPTION_KEY:
        return jsonify(error="key_encryption_not_configured"), 503
    try:
        key_cipher = Fernet(LICENSE_KEY_ENCRYPTION_KEY.encode("ascii"))
    except Exception:
        app.logger.exception("LICENSE_KEY_ENCRYPTION_KEY is invalid")
        return jsonify(error="key_encryption_configuration_invalid"), 503

    with db() as conn:
        challenge = conn.execute(
            "SELECT * FROM free_key_captchas WHERE challenge_id=%s FOR UPDATE",
            (challenge_id,),
        ).fetchone()
        if (not challenge or challenge["machine_id"] != machine_id
                or challenge["used_at"] or challenge["expires_at"] <= datetime.now(timezone.utc)
                or challenge["failed_attempts"] >= 3):
            return jsonify(error="captcha_expired"), 400
        expected_hash = hashlib.sha256(
            f"{challenge_id}:{machine_id}:{answer}".encode("utf-8")
        ).hexdigest()
        if not hmac.compare_digest(expected_hash, challenge["answer_hash"]):
            conn.execute(
                "UPDATE free_key_captchas SET failed_attempts=failed_attempts+1 WHERE challenge_id=%s",
                (challenge_id,),
            )
            return jsonify(error="captcha_incorrect"), 400
        conn.execute("UPDATE free_key_captchas SET used_at=now() WHERE challenge_id=%s", (challenge_id,))
        # Serialize simultaneous requests from the same device so it cannot
        # reserve multiple free keys through overlapping clicks/retries.
        conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (machine_id,))
        # If the client lost the response or closed before activating, return
        # the same reservation to that device rather than consuming another key.
        row = conn.execute(
            "SELECT key_hash, encrypted_key FROM licenses "
            "WHERE is_free=TRUE AND machine_id=%s AND activated_at IS NULL AND revoked_at IS NULL "
            "ORDER BY issued_at LIMIT 1 FOR UPDATE",
            (machine_id,),
        ).fetchone()
        if row is None:
            row = conn.execute(
                "SELECT key_hash, encrypted_key FROM licenses "
                "WHERE is_free=TRUE AND machine_id IS NULL AND activated_at IS NULL AND revoked_at IS NULL "
                "ORDER BY issued_at, key_hash LIMIT 1 FOR UPDATE SKIP LOCKED"
            ).fetchone()
            if row is None:
                return jsonify(error="free_keys_unavailable"), 404
            conn.execute(
                "UPDATE licenses SET machine_id=%s WHERE key_hash=%s AND machine_id IS NULL",
                (machine_id, row["key_hash"]),
            )
        if not row["encrypted_key"]:
            return jsonify(error="free_key_unavailable"), 503
        try:
            key = key_cipher.decrypt(row["encrypted_key"].encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError, UnicodeError):
            return jsonify(error="free_key_unavailable"), 503
    return jsonify(key=key, reserved=True)


@app.get("/api/v1/admin/licenses")
def list_licenses():
    denied = require_admin()
    if denied:
        return denied
    now = datetime.now(timezone.utc)
    with db() as conn:
        rows = conn.execute(
            "SELECT key_hash, key_hint, encrypted_key, duration_seconds, issued_at, activated_at, expires_at, last_seen, online_since, offline_at, revoked_at, username FROM licenses ORDER BY issued_at DESC"
        ).fetchall()
    try:
        key_cipher = Fernet(LICENSE_KEY_ENCRYPTION_KEY.encode("ascii")) if LICENSE_KEY_ENCRYPTION_KEY else None
    except Exception:
        key_cipher = None
    output = []
    for row in rows:
        online = bool(row["last_seen"] and (now - row["last_seen"]).total_seconds() <= ONLINE_WINDOW_SECONDS and not row["revoked_at"] and (not row["expires_at"] or row["expires_at"] > now))
        online_seconds = max(0, int((now - row["online_since"]).total_seconds())) if online and row["online_since"] else 0
        offline_at = row["offline_at"]
        if not online and offline_at is None:
            # Nếu heartbeat mất đột ngột, ước tính OFF sau khi hết cửa sổ
            # heartbeat 100 giây tính từ lần cuối server nhận được.
            candidates = []
            if row["last_seen"]:
                candidates.append(row["last_seen"] + timedelta(seconds=ONLINE_WINDOW_SECONDS))
            if row["revoked_at"]:
                candidates.append(row["revoked_at"])
            if row["expires_at"] and row["expires_at"] <= now:
                candidates.append(row["expires_at"])
            offline_at = min(candidates) if candidates else None
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
            "offline_at": offline_at,
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
        result = conn.execute("UPDATE licenses SET revoked_at=now(), offline_at=CASE WHEN last_seen IS NOT NULL THEN LEAST(now(), last_seen + (%s * INTERVAL '1 second')) ELSE offline_at END, last_seen=NULL, online_since=NULL WHERE key_hash=%s", (ONLINE_WINDOW_SECONDS, license_id))
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

