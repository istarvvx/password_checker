import os

from flask import Flask, jsonify, request, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from checker import check_password, load_common_passwords
from leaked import LeakedDB

BASE = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 2048                  # reject oversized bodies early
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)           # real client IP behind the host's proxy

limiter = Limiter(get_remote_address, app=app,
                  default_limits=["300 per hour"], storage_uri="memory://")

# Loaded once at startup (shared across workers via gunicorn --preload).
COMMON = load_common_passwords(os.path.join(BASE, "common_passwords.txt"))
LEAKED = LeakedDB(os.path.join(BASE, os.environ.get("LEAKED_DB", "leaked.bin")))


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.post("/api/check")
@limiter.limit("30 per minute")
def check():
    data = request.get_json(silent=True) or {}
    password = data.get("password")
    if not isinstance(password, str):
        return jsonify(error="Send JSON with a 'password' string."), 400
    try:
        return jsonify(check_password(password, COMMON, LEAKED))
    except ValueError as e:
        return jsonify(error=str(e)), 400


@app.get("/healthz")
@limiter.exempt
def healthz():
    return "ok"


@app.errorhandler(413)
def too_large(_):
    return jsonify(error="Request too large."), 413


@app.errorhandler(429)
def rate_limited(_):
    return jsonify(error="Too many checks. Wait a minute and try again."), 429


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


if __name__ == "__main__":
    app.run(debug=True)  # local development only
