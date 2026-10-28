"""Offline leaked-password lookup.

leaked.bin is a sorted array of 8-byte SHA-1 prefixes (see build_leaked_db.py).
It is memory-mapped, so workers share it through the OS page cache and a lookup
is a ~24-step binary search (microseconds) with almost no RAM, even for rockyou.
"""
import hashlib
import mmap
import os

REC = 8  # bytes per record


def _key(pw: str) -> int:
    return int.from_bytes(hashlib.sha1(pw.encode("utf-8")).digest()[:REC], "big")


class LeakedDB:
    def __init__(self, path):
        self._mm, self.count = None, 0
        try:
            with open(path, "rb") as f:
                size = os.fstat(f.fileno()).st_size
                if size >= REC:
                    self._mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                    self.count = size // REC
        except FileNotFoundError:
            pass
        if not self.count:
            print(f"Warning: {path} missing or empty; leaked-password lookup disabled.")

    def __contains__(self, pw: str) -> bool:
        if not self.count:
            return False
        target, mm = _key(pw), self._mm
        lo, hi = 0, self.count - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            val = int.from_bytes(mm[mid * REC:(mid + 1) * REC], "big")
            if val == target:
                return True
            if val < target:
                lo = mid + 1
            else:
                hi = mid - 1
        return False
