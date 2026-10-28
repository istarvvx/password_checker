# Password strength checker (Flask)

## Run locally
    python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
    pip install -r requirements.txt
    python app.py                                        # http://127.0.0.1:5000

## Leaked-password matching
The app checks every password against `leaked.bin`, a compact file of hashed entries from
breach lists (exact match = "leaked", close variants like `P@ssw0rd1!` also flagged).
The bundled `leaked.bin` is only a tiny sample. Build the real one from rockyou:

    pip install numpy                                     # build-time only
    python build_leaked_db.py /usr/share/wordlists/rockyou.txt.gz   # full: ~110 MB
    python build_leaked_db.py rockyou.txt.gz extra.txt --limit 1000000   # top 1M each: ~8 MB

Add as many lists as you like. It is memory-mapped, so lookups take microseconds and RAM stays tiny.
For free hosts, commit the top-1M build (or use Git LFS for the full one).

## Deploy (Render / Railway)
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn --preload --workers 2 --threads 2 --bind 0.0.0.0:$PORT app:app`
- Health check path: `/healthz`
Free tiers sleep when idle, so the first request after a pause is slow.

## Notes
- Rate limits are in-memory and per worker; use Redis (`storage_uri`) if you scale up.
- Serve over HTTPS only (the host provides it). The app never logs or stores passwords.
