"""Pinned CMSIS device pack for the STM32F446.

pyocd only knows the STM32F446 through a device pack. Instead of relying on pyocd's online
pack index (which can come back without this device), this downloads one exact pack straight
from Keil and refuses it unless its SHA-256 matches.

You do not need to run this by hand: preflight and the replay scripts call ensure() and fetch
the pack on first use. Running it directly (python replay/devicepack.py) just pre-fetches it.
"""
import hashlib
import os
import shutil
import ssl
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

TARGET = "stm32f446retx"
PACK_NAME = "Keil.STM32F4xx_DFP.3.1.1.pack"
PACK_URL = "https://www.keil.com/pack/" + PACK_NAME
PACK_SHA256 = "345231106fe697df24bbe9133aeeec1b0383d7891c4adf4f47bbb8b478e9f2f0"
PACK_SIZE = 2085496
PACK_REL = "packs/" + PACK_NAME
PACK_PATH = os.path.join(ROOT, "packs", PACK_NAME)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pack_ok():
    return os.path.isfile(PACK_PATH) and sha256(PACK_PATH) == PACK_SHA256


def _ssl_context():
    """Verify TLS against certifi's CA bundle when available (fixes the common Windows
    'unable to get local issuer certificate' error), else the system default."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def fetch():
    """Download the pinned pack into packs/, replacing any file that does not match the hash."""
    os.makedirs(os.path.dirname(PACK_PATH), exist_ok=True)
    part = PACK_PATH + ".part"
    try:
        req = urllib.request.Request(PACK_URL, headers={"User-Agent": "ruptor-benchmark"})
        with urllib.request.urlopen(req, context=_ssl_context(), timeout=60) as resp, open(part, "wb") as f:
            shutil.copyfileobj(resp, f)
        got = sha256(part)
        if got != PACK_SHA256:
            sys.exit(f"downloaded {PACK_NAME} has SHA-256 {got}, expected {PACK_SHA256}. Not using it.")
        os.replace(part, PACK_PATH)
    finally:
        if os.path.exists(part):
            os.remove(part)
    return PACK_PATH


def ensure():
    """Return the verified pack path, fetching it on first use. Exits with guidance on failure."""
    if pack_ok():
        return PACK_PATH
    print(f"[pack] fetching {PACK_NAME} ({PACK_SIZE // 1024} KB) from keil.com ...", flush=True)
    try:
        path = fetch()
    except (ssl.SSLError, urllib.error.URLError, OSError) as e:
        reason = getattr(e, "reason", e)
        sys.exit(f"could not download the STM32F4 device pack: {reason}\n"
                 f"  - If this is a TLS/certificate error, run: pip install -r requirements.txt "
                 f"(installs certifi), then retry.\n"
                 f"  - Or download {PACK_URL} manually and save it as {PACK_REL}, then retry.")
    print(f"[pack] ok, sha256 {PACK_SHA256[:12]}...", flush=True)
    return path


def session_options():
    """pyocd session options that load the pinned pack (fetched on first use)."""
    return {"pack": ensure()}


if __name__ == "__main__":
    path = ensure()
    print(f"ok  {PACK_NAME}  sha256 {PACK_SHA256[:12]}...  ->  {os.path.relpath(path, ROOT)}")
