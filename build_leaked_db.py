"""Build leaked.bin from one or more password lists (plain text or .gz).

    pip install numpy            # build-time only
    python build_leaked_db.py /usr/share/wordlists/rockyou.txt.gz --out leaked.bin
    python build_leaked_db.py rockyou.txt other_list.txt --limit 1000000

Lists are ordered by frequency, so --limit N keeps the N most common per file.
Full rockyou (~14M) -> ~110 MB file; top 1M -> ~8 MB.
"""
import argparse
import gzip
import hashlib

import numpy as np


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--limit", type=int, default=0, help="first N lines of each file only")
    ap.add_argument("--out", default="leaked.bin")
    a = ap.parse_args()

    parts, buf, lines = [], [], 0
    for path in a.files:
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rb") as f:
            for i, raw in enumerate(f):
                if a.limit and i >= a.limit:
                    break
                pw = raw.rstrip(b"\r\n")
                if not pw:
                    continue
                buf.append(int.from_bytes(hashlib.sha1(pw).digest()[:8], "big"))
                lines += 1
                if len(buf) >= 1_000_000:
                    parts.append(np.array(buf, dtype=np.uint64))
                    buf = []
    if buf:
        parts.append(np.array(buf, dtype=np.uint64))
    arr = np.unique(np.concatenate(parts))           # sorted + de-duplicated
    arr.astype(">u8").tofile(a.out)                  # big-endian, matches leaked.py
    print(f"{lines:,} lines -> {len(arr):,} unique hashes -> {a.out} ({len(arr) * 8 / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
