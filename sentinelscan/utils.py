from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, Tuple


def compute_hashes(path: Path, chunk_size: int = 1024 * 1024) -> Dict[str, str]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            md5.update(chunk)
            sha256.update(chunk)

    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def safe_read_bytes(path: Path, max_bytes: int) -> bytes:
    with path.open("rb") as f:
        return f.read(max_bytes)


def extract_ascii_strings(data: bytes, min_len: int = 4) -> Tuple[str, ...]:
    out = []
    current = []

    for b in data:
        if 32 <= b <= 126:
            current.append(b)
        else:
            if len(current) >= min_len:
                out.append(bytes(current).decode("ascii", errors="ignore"))
            current = []
    if len(current) >= min_len:
        out.append(bytes(current).decode("ascii", errors="ignore"))

    return tuple(out)