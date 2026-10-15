"""Pinned CMSIS device pack for the STM32F446.

pyocd only knows the STM32F446 through a device pack. Instead of relying on pyocd's online
pack index (which can come back without this device), this downloads one exact pack straight
from Keil and refuses it unless its SHA-256 matches. Run it once:  python replay/devicepack.py
"""
import hashlib
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

TARGET = "stm32f446retx"
PACK_NAME = "Keil.STM32F4xx_DFP.3.1.1.pack"
PACK_URL = "https://www.keil.com/pack/" + PACK_NAME
PACK_SHA256 = "345231106fe697df24bbe9133aeeec1b0383d7891c4adf4f47bbb8b478e9f2f0"
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


def fetch():
    """Download the pinned pack into packs/ unless a verified copy is already there."""
    if pack_ok():
        return PACK_PATH
    os.makedirs(os.path.dirname(PACK_PATH), exist_ok=True)
    part = PACK_PATH + ".part"
    try:
        urllib.request.urlretrieve(PACK_URL, part)
        got = sha256(part)
        if got != PACK_SHA256:
            sys.exit(f"downloaded {PACK_NAME} has SHA-256 {got}, expected {PACK_SHA256}. Not using it.")
        os.replace(part, PACK_PATH)
    finally:
        if os.path.exists(part):
            os.remove(part)
    return PACK_PATH


def session_options():
    """pyocd session options that load the pinned pack, or none if it has not been fetched."""
    return {"pack": PACK_PATH} if os.path.isfile(PACK_PATH) else {}


if __name__ == "__main__":
    path = fetch()
    print(f"ok  {PACK_NAME}  sha256 {PACK_SHA256[:12]}...  ->  {os.path.relpath(path, ROOT)}")
