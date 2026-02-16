"""Intentionally vulnerable Flask application for security scan testing."""

import os
import sqlite3
import subprocess

from flask import Flask, jsonify, redirect, render_template_string, request

app = Flask(__name__)
app.secret_key = "super_secret_key_12345"  # Hardcoded secret (Semgrep: hardcoded-credential)
app.debug = True  # Debug mode enabled (Semgrep: flask-debug)

# Hardcoded database credentials
DB_USER = "admin"
DB_PASSWORD = "password123"  # Hardcoded password (Semgrep)
DATABASE = "/tmp/vuln_test.db"


def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email TEXT,
            password TEXT
        )
    """)
    db.execute("""
        INSERT OR IGNORE INTO users (id, username, email, password)
        VALUES (1, 'admin', 'admin@test.com', 'admin123')
    """)
    db.execute("""
        INSERT OR IGNORE INTO users (id, username, email, password)
        VALUES (2, 'user', 'user@test.com', 'user123')
    """)
    db.commit()
    db.close()


@app.route("/")
def index():
    return render_template_string("""
    <html>
    <head><title>Vulnerable Test App</title></head>
    <body>
        <h1>Killhouse Vulnerable Test Application</h1>
        <p>This app has intentional vulnerabilities for testing.</p>
        <ul>
            <li><a href="/search?q=test">Search (XSS)</a></li>
            <li><a href="/user?id=1">User Lookup (SQL Injection)</a></li>
            <li><a href="/ping?host=localhost">Ping (Command Injection)</a></li>
            <li><a href="/admin">Admin Panel</a></li>
            <li><a href="/api/health">Health Check</a></li>
        </ul>
    </body>
    </html>
    """)


@app.route("/search")
def search():
    query = request.args.get("q", "")
    # Reflected XSS - user input directly rendered in HTML (Semgrep: reflected-xss)
    return render_template_string(f"""
    <html>
    <head><title>Search Results</title></head>
    <body>
        <h2>Search results for: {query}</h2>
        <p>No results found for <b>{query}</b></p>
        <a href="/">Back</a>
    </body>
    </html>
    """)


@app.route("/user")
def user_lookup():
    user_id = request.args.get("id", "1")
    db = get_db()
    # SQL Injection - string formatting in SQL (Semgrep: sql-injection)
    cursor = db.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user = cursor.fetchone()
    db.close()
    if user:
        return jsonify({"id": user["id"], "username": user["username"], "email": user["email"]})
    return jsonify({"error": "User not found"}), 404


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # Command Injection - user input in shell command (Semgrep: command-injection)
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return render_template_string(f"""
    <html>
    <body>
        <h2>Ping Result for {host}</h2>
        <pre>{result.stdout}</pre>
        <a href="/">Back</a>
    </body>
    </html>
    """)


@app.route("/admin")
def admin():
    # No authentication check (missing auth)
    return render_template_string("""
    <html>
    <body>
        <h2>Admin Panel</h2>
        <p>Welcome to the admin panel. No authentication required!</p>
        <form action="/admin/exec" method="post">
            <label>Run command:</label>
            <input type="text" name="cmd" />
            <button type="submit">Execute</button>
        </form>
    </body>
    </html>
    """)


@app.route("/admin/exec", methods=["POST"])
def admin_exec():
    cmd = request.form.get("cmd", "echo hello")
    # Direct OS command execution (Semgrep: dangerous-subprocess)
    output = os.popen(cmd).read()
    return f"<pre>{output}</pre>"


@app.route("/api/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "version": "1.0.0",
            "debug": app.debug,
            "server": "Flask/" + os.environ.get("FLASK_VERSION", "unknown"),
        }
    )


@app.route("/api/data", methods=["POST"])
def api_data():
    # No CSRF protection, no input validation
    data = request.get_json(force=True)
    return jsonify({"received": data})


@app.route("/redirect")
def open_redirect():
    url = request.args.get("url", "/")
    # Open redirect vulnerability (Semgrep: open-redirect)
    return redirect(url)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080, debug=True)
