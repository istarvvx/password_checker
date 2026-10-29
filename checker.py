"""Password strength logic: leaked-list matching + a deliberately strict entropy estimate."""
import math
import re

MAX_LEN = 128
LABELS = ["Compromised", "Very weak", "Weak", "Fair", "Good", "Strong"]  # index = level
_CUTS = (28, 40, 52, 64)  # estimated bits needed for levels 2..5

_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")
_WALKS = frozenset(r[i:i + 3] for row in _ROWS for r in (row, row[::-1]) for i in range(len(row) - 2))
_TAIL = re.compile(r"[\d\W_]{1,6}$")        # trailing digits/symbols ("2024!")
_NONLETTER_END = re.compile(r"[^a-z]+$")
_LOOP = re.compile(r"^(.+?)\1+$", re.S)      # "abcabcabc"
_TOKENS = re.compile(r"[A-Za-z]+|\d|[\s\-_.]|.", re.S)
_LEET = str.maketrans({"0": "o", "4": "a", "3": "e", "1": "i", "5": "s", "$": "s", "@": "a", "7": "t", "!": "i"})


def load_common_passwords(path):
    """Small fallback list, loaded once into a frozenset."""
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return frozenset(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        return frozenset()


def _leak_match(pw, common, db):
    """'exact', 'variant' or None. Variants: case, trailing digits/symbols, leetspeak."""
    if pw in common or pw in db:
        return "exact"
    low = pw.lower()
    trimmed = _NONLETTER_END.sub("", low)
    cands = {low, trimmed, low.translate(_LEET), trimmed.translate(_LEET)}
    if any(len(c) >= 4 and (c in common or c in db) for c in cands):
        return "variant"
    return None


def _collapse(pw):
    """Drop characters an attacker gets for free: repeats, sequences, keyboard walks."""
    loop = _LOOP.match(pw)
    if loop:
        pw = loop.group(1)
    low, out = pw.lower(), []
    for i, c in enumerate(pw):
        if i and c == pw[i - 1]:
            continue
        if i >= 2:
            d1, d2 = ord(c) - ord(pw[i - 1]), ord(pw[i - 1]) - ord(pw[i - 2])
            if d1 == d2 and abs(d1) == 1:
                continue
            if low[i - 2:i + 1] in _WALKS:
                continue
        out.append(c)
    return "".join(out)


def _pool_bits(s):
    """Brute-force estimate. Leading capital and trailing digits/symbols are predictable, so cheap."""
    bits, body = 0.0, s
    m = _TAIL.search(body)
    if m and m.start() > 0:
        bits += 3.3 * len(m.group())
        body = body[:m.start()]
    predictable = bool(m and m.start() > 0)
    if len(body) > 1 and body[0].isupper() and not any(c.isupper() for c in body[1:]):
        bits += 1
        body = body[1:]
        predictable = True
    kinds = set()
    for c in body:
        kinds.add(("l" if c.islower() else "u" if c.isupper() else "d" if c.isdigit() else "s") if c.isascii() else "x")
    pool = sum({"l": 26, "u": 26, "d": 10, "s": 33, "x": 100}[k] for k in kinds) or 1
    return bits + len(body) * math.log2(pool), predictable


def _word_bits(s):
    """Human-style estimate: each word-like letter run costs ~11 bits, not 4.7 per letter."""
    bits, found = 0.0, False
    for t in (m.group() for m in _TOKENS.finditer(s)):
        if t.isascii() and t.isalpha():
            if len(t) >= 3 and (t.islower() or t.istitle() or t.isupper()):
                found = True
                bits += 11 * math.ceil(len(t) / 7)
            else:
                bits += len(t) * (4.7 if t.islower() else 5.7)
        elif t.isdigit():
            bits += 3.3
        elif t in " -_.":
            bits += 1
        else:
            bits += 5
    return bits if found else None


def check_password(password, common, db):
    """Return {label, level, entropy, leaked, match, feedback}. Raises ValueError on bad input."""
    if not password:
        raise ValueError("Password cannot be empty.")
    if len(password) > MAX_LEN:
        raise ValueError(f"Password must be {MAX_LEN} characters or fewer.")

    match = _leak_match(password, common, db)
    if match:
        msg = ("This exact password appears in leaked-password Database. Attackers try these first."
               if match == "exact" else
               "This is a close variant of a leaked password "
               )
        return {"label": LABELS[0], "level": 0, "entropy": 0, "leaked": True, "match": match,
                "feedback": [msg, "Change it now, and change it anywhere else you have used it."]}

    reduced = _collapse(password)
    pool, predictable = _pool_bits(reduced)
    words = _word_bits(reduced)
    bits = pool if words is None else min(pool, words)

    level = 1 + sum(bits >= c for c in _CUTS)
    if len(password) < 8:
        level = min(level, 2)
    elif len(password) < 12:
        level = min(level, 4)

    tips = []
    if len(password) < 12:
        tips.append("Use at least 12 characters (more is better).")
    if len(reduced) < len(password) - 1:
        tips.append("Avoid repeats and sequences like 'aaa', 'abc', '1234' or 'qwerty'.")
    if predictable:
        tips.append("Avoid 'General Password Patters.")
    if words is not None and words <= pool:
        tips.append("Words are easy to guess. Use 6+ unrelated words, or random characters.")
    if level == 5:
        tips = ["Looks strong. Don't Use it for more than one account."]
    elif not tips:
        tips.append("Make it longer. Each extra random character adds a lot.")

    return {"label": LABELS[level], "level": level, "entropy": round(bits), "leaked": False,
            "match": None, "feedback": tips}
