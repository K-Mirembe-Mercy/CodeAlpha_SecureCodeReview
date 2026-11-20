"""
app_secure.py - Remediated version of app_vulnerable.py.

Each fix is marked with "[FIX n]" and matches "[VULN n]" in app_vulnerable.py.
See REVIEW_REPORT.md for the full findings.

Configuration (environment variables):
  SECRET_KEY            Session signing key. If unset, a random key is generated
                        at startup (sessions are lost on restart).
  APP_DB                Path to the SQLite database file.
  SESSION_COOKIE_SECURE Set to "1" when serving over HTTPS.
"""
import functools
import os
import re
import secrets
import sqlite3
import subprocess

from flask import (Flask, Response, abort, jsonify, render_template_string,
                   request, send_from_directory, session)
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("APP_DB", os.path.join(BASE_DIR, "demo_secure.db"))
FILES_DIR = os.path.join(BASE_DIR, "files")
ALLOWED_EXTENSIONS = {".txt", ".md"}
HOST_PATTERN = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
NAME_PATTERN = re.compile(r"[\w .'-]{1,50}")

app = Flask(__name__)
app.config.update(
    # [FIX 5] Secret key comes from the environment or is random, never hardcoded
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
    MAX_CONTENT_LENGTH=16 * 1024,
)

# Used to keep login timing similar when the username does not exist
DUMMY_HASH = generate_password_hash(secrets.token_hex(16))


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, "
        "password TEXT, email TEXT, role TEXT)"
    )
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        # Demo data only. Never ship default credentials in a real system.
        seed = [
            ("admin", "admin123", "admin@example.com", "admin"),
            ("alice", "alicepass", "alice@example.com", "user"),
            ("bob", "bobpass", "bob@example.com", "user"),
        ]
        for username, password, email, role in seed:
            conn.execute(
                "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                # [FIX 6] Salted, slow password hashing instead of MD5
                (username, generate_password_hash(password), email, role),
            )
    conn.commit()
    conn.close()


init_db()


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return jsonify(error="Authentication required"), 401
        return view(*args, **kwargs)
    return wrapped


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def index():
    return jsonify(
        app="secure demo",
        endpoints=["POST /login", "GET /ping", "GET /download", "GET /search",
                   "GET /user/<id>", "POST /import"],
    )


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # [FIX 1] Parameterized query: input is treated as data, never as SQL
    row = get_db().execute(
        "SELECT id, username, role, password FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    stored_hash = row["password"] if row else DUMMY_HASH
    if not check_password_hash(stored_hash, password) or row is None:
        return jsonify(error="Invalid credentials"), 401
    session.clear()
    session["user_id"] = row["id"]
    session["role"] = row["role"]
    return jsonify(message=f"Welcome {row['username']}", role=row["role"])


@app.get("/ping")
@login_required
def ping():
    host = request.args.get("host", "127.0.0.1")
    # [FIX 2] Strict allowlist validation, and no shell (argument list)
    if not HOST_PATTERN.fullmatch(host):
        return jsonify(error="Invalid host"), 400
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host],
            capture_output=True, text=True, timeout=5, shell=False,
        )
    except FileNotFoundError:
        return jsonify(error="ping is not available on this server"), 503
    except subprocess.TimeoutExpired:
        return jsonify(error="ping timed out"), 504
    return Response(result.stdout + result.stderr, mimetype="text/plain")


@app.get("/download")
@login_required
def download():
    name = request.args.get("name", "")
    if os.path.splitext(name)[1].lower() not in ALLOWED_EXTENSIONS:
        abort(404)
    # [FIX 3] send_from_directory refuses any path that leaves FILES_DIR
    return send_from_directory(FILES_DIR, name, as_attachment=True)


@app.get("/search")
def search():
    q = request.args.get("q", "")[:200]
    # [FIX 4] Jinja2 auto-escapes the value (plus a strict CSP header)
    return render_template_string(
        "<h1>Search results for: {{ q }}</h1><p>No results found.</p>", q=q
    )


@app.get("/user/<int:user_id>")
@login_required
def get_user(user_id):
    # [FIX 7] Only the owner or an admin may view a profile
    if session["user_id"] != user_id and session.get("role") != "admin":
        return jsonify(error="Forbidden"), 403
    row = get_db().execute(
        "SELECT id, username, email, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if row is None:
        return jsonify(error="Not found"), 404
    return jsonify(dict(row))


@app.post("/import")
@login_required
def import_profile():
    # [FIX 8] Plain JSON with strict validation instead of pickle
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Expected a JSON object"), 400
    display_name = data.get("display_name")
    if not isinstance(display_name, str) or not NAME_PATTERN.fullmatch(display_name):
        return jsonify(error="Invalid display_name"), 400
    return jsonify(display_name=display_name)


@app.errorhandler(HTTPException)
def handle_http_error(err):
    return jsonify(error=err.name), err.code


@app.errorhandler(Exception)
def handle_unexpected_error(err):
    # Log details server-side only; never return stack traces to clients
    app.logger.exception("Unhandled error")
    return jsonify(error="Internal server error"), 500


if __name__ == "__main__":
    # [FIX 9] Debug mode off
    app.run(host="127.0.0.1", port=5000, debug=False)
