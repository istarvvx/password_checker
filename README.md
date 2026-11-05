# 🔐 Password Strength Checker

A lightweight, privacy-focused web application built with Flask that evaluates password strength and checks against known leaked password databases. 

Unlike basic length-checkers, this tool detects predictable patterns (like keyboard walks, repeated characters, and capitalized words with trailing numbers) and uses a highly efficient memory-mapped database to instantly query millions of leaked passwords using almost no RAM.

## ✨ Features

- **Leaked Password Detection:** Checks passwords against a memory-mapped database of breached hashes. Detects exact matches and close variants (e.g., `P@ssw0rd1!`).
- **Advanced Strength Heuristics:** Calculates entropy by identifying keyboard walks (`qwerty`), repeated sequences (`abcabc`), and predictable structures.
- **High Performance:** Uses `mmap` for binary searches against the leaked database, taking only microseconds per query.
- **Rate Limiting:** Built-in rate limiting via `Flask-Limiter` to prevent brute-force API abuse.
- **Privacy First:** Passwords are never logged, stored, or transmitted to third-party APIs. All checks happen locally.

## 🚀 Run Locally

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/password_checker.git
   cd password_checker
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate   # On Windows use: .venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application:**
   ```bash
   python app.py
   ```
   The app will be available at `http://127.0.0.1:5000`.

## 🗄️ Leaked-Password Database Setup

The app checks passwords against `leaked.bin`, a compact file of SHA-1 prefixes. A tiny sample is provided by default, but you should build a real database using a wordlist like `rockyou.txt` for production.

1. Install the build-time dependency:
   ```bash
   pip install numpy
   ```

2. Build the database (examples):
   ```bash
   # Build the full database from rockyou (~110 MB)
   python build_leaked_db.py /usr/share/wordlists/rockyou.txt.gz 
   
   # Build keeping only the top 1 million most common passwords (~8 MB)
   python build_leaked_db.py rockyou.txt.gz extra.txt --limit 1000000 
   ```
   *Note: For free hosting tiers (like Render or Heroku), committing the 8MB top-1M build is recommended. Use Git LFS if you want to push the full 110MB file.*

## 📂 Project Structure

- `app.py`: Main Flask application, API endpoints, and rate-limiting logic.
- `checker.py`: Core password strength logic, entropy calculations, and pattern detection.
- `leaked.py`: Efficient `mmap` binary search implementation for the `leaked.bin` file.
- `build_leaked_db.py`: Utility script to convert plain-text wordlists into the optimized `.bin` format.
- `common_passwords.txt`: A small fallback list of highly common passwords.

## ☁️ Deployment (Render / Railway / etc.)

- **Build command:** `pip install -r requirements.txt`
- **Start command:** `gunicorn --preload --workers 2 --threads 2 --bind 0.0.0.0:$PORT app:app`
- **Health check path:** `/healthz`

*Note: Free hosting tiers often sleep when idle, so the first request after a pause may take a few extra seconds.*

## 🔒 Security Notes

- **HTTPS:** Always serve this application over HTTPS in production.
- **Scaling:** Rate limits are currently in-memory and per-worker. If scaling to multiple nodes, configure a Redis backend for `Flask-Limiter` (`storage_uri`).

- ## LIVE DEMO : [Password Strength Checker](https://web-app-t8ka.onrender.com/)
