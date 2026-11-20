"""
app_vulnerable.py - INTENTIONALLY VULNERABLE Flask application.

For security training and code-review practice ONLY.
Never deploy this app, expose it to a network, or use real data with it.
It binds to 127.0.0.1 so it is reachable only from your own machine.

The 9 flaws are marked with "[VULN n]" comments. See REVIEW_REPORT.md.
"""
import base64
import hashlib
import os
import pickle
import sqlite3
import subprocess

from flask import Flask, Response, jsonify, request, send_file, session

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("APP_DB", os.path.join(BASE_DIR, "demo_vulnerable.db"))
FILES_DIR = os.path.join(BASE_DIR, "files")

app = Flask(__name__)
app.secret_key = "supersecret123"  # [VULN 5] Hardcoded, guessable secret key


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
        seed = [
            ("admin", "admin123", "admin@example.com", "admin"),
            ("alice", "alicepass", "alice@example.com", "user"),
            ("bob", "bobpass", "bob@example.com", "user"),
        ]
        for username, password, email, role in seed:
            conn.execute(
                "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                # [VULN 6] Unsalted MD5 password hashes
                (username, hashlib.md5(password.encode()).hexdigest(), email, role),
            )
    conn.commit()
    conn.close()


init_db()


@app.get("/")
def index():
    return jsonify(
        app="vulnerable demo",
        endpoints=["POST /login", "GET /ping", "GET /download", "GET /search",
                   "GET /user/<id>", "POST /import"],
    )


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    pw_hash = hashlib.md5(password.encode()).hexdigest()
    # [VULN 1] SQL injection: user input concatenated into the query (CWE-89)
    query = (
        f"SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password = '{pw_hash}'"
    )
    row = get_db().execute(query).fetchone()
    if row is None:
        return jsonify(error="Invalid credentials"), 401
    session["user_id"] = row["id"]
    session["role"] = row["role"]
    return jsonify(message=f"Welcome {row['username']}", role=row["role"])


@app.get("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # [VULN 2] OS command injection: user input passed to a shell (CWE-78)
    result = subprocess.run(
        f"ping -c 1 {host}", shell=True, capture_output=True, text=True
    )
    return Response(result.stdout + result.stderr, mimetype="text/plain")


@app.get("/download")
def download():
    name = request.args.get("name", "")
    # [VULN 3] Path traversal: no validation of the requested path (CWE-22)
    return send_file(os.path.join(FILES_DIR, name))


@app.get("/search")
def search():
    q = request.args.get("q", "")
    # [VULN 4] Reflected XSS: input echoed into HTML without escaping (CWE-79)
    return f"<h1>Search results for: {q}</h1><p>No results found.</p>"


@app.get("/user/<int:user_id>")
def get_user(user_id):
    # [VULN 7] IDOR: no authentication or ownership check (CWE-639 / CWE-862)
    row = get_db().execute(
        "SELECT id, username, email, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if row is None:
        return jsonify(error="Not found"), 404
    return jsonify(dict(row))


@app.post("/import")
def import_profile():
    data = request.form.get("data", "")
    # [VULN 8] Insecure deserialization of untrusted data (CWE-502)
    profile = pickle.loads(base64.b64decode(data))
    return jsonify(profile=str(profile))


if __name__ == "__main__":
    # [VULN 9] Debug mode on: interactive debugger and verbose errors (CWE-489)
    app.run(host="127.0.0.1", port=5000, debug=True)
