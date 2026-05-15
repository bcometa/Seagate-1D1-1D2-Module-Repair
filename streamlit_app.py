"""
$300 Data Recovery — 1D1 Repair & Unlock (Streamlit)

Inspect and repair Seagate Rosewood / M11 / SED firmware modules:
1D1, 1D2, 0x227, 0x30A. All processing is in-memory; nothing is uploaded
beyond the user's browser session.

References (HDD Guru / forums):
  - https://forum.hddguru.com/viewtopic.php?f=1&t=43339
  - fzabkar's writeup on 1D2 carving + permanent ROM unlock
  - jackass25 alternative basic-unlock method
"""

from __future__ import annotations

import io
import os
import re
import zipfile
from typing import Optional

import streamlit as st


# ============================================================
# Access control
# ============================================================
# Default password. For deployments on Streamlit Community Cloud or any
# multi-user setting, set the password via st.secrets["password"] or the
# APP_PASSWORD environment variable so the value is not committed to the repo.
APP_PASSWORD_DEFAULT = "11390"


def _expected_password() -> str:
    """Resolve the expected password: st.secrets > APP_PASSWORD env > default constant."""
    try:
        if "password" in st.secrets:
            return st.secrets["password"]
    except Exception:
        pass
    return os.environ.get("APP_PASSWORD", APP_PASSWORD_DEFAULT)


def _on_password_submit():
    if st.session_state.get("pw_input") == _expected_password():
        st.session_state["password_ok"] = True
        st.session_state["pw_input"] = ""   # don't keep the entered value around
        st.session_state.pop("pw_wrong", None)
    else:
        st.session_state["pw_wrong"] = True


def check_password() -> bool:
    """Render password gate. Returns True only when the user has authenticated."""
    if st.session_state.get("password_ok"):
        return True
    st.title("$300 Data Recovery — 1D1 Repair & Unlock")
    st.caption("Internal tool — please enter the access password to continue.")
    st.text_input(
        "Password",
        type="password",
        key="pw_input",
        on_change=_on_password_submit,
        placeholder="Enter password and press Return",
    )
    if st.session_state.get("pw_wrong"):
        st.error("Wrong password.")
    return False


# ============================================================
# Constants — module layout (offsets, sizes, magic)
# ============================================================
MAGIC = bytes([0xC2, 0xBD, 0x12, 0x0B])

SIZE_1D2          = 0x2000
CARVE_OFFSET      = 0x22000        # 1D2 inside 1D1
PWD_OFFSET        = 0x39000        # partial 0x30A inside 1D1
PWD_LENGTH        = 0x110
OFF_1D2_IN_227    = 0x1C5000       # 1D2 inside 0x227
OFF_30A_IN_227    = 0x2F1000       # 0x30A inside 0x227
SIZE_30A_FULL     = 0x1000
LOCK_OFFSET       = 0x04
CKSUM_OFFSET      = 0x1C88
CAP_OFFSET        = 0x1C20
SENT_OFFSET       = 0x1BE0
KEY_REGION_START  = 0x100
KEY_REGION_END    = 0x900
KEY_DUP_START     = 0x980
KEY_DUP_END       = 0x1180

SLOT_KEYS = ["1d1x0", "1d1x1", "1d2x0", "1d2x1", "0x227", "0x30a"]
SLOT_LABELS = {
    "1d1x0": ("1D1", "copy 0"),
    "1d1x1": ("1D1", "copy 1"),
    "1d2x0": ("1D2", "copy 0"),
    "1d2x1": ("1D2", "copy 1"),
    "0x227": ("0x227", "container"),
    "0x30a": ("0x30A", "passwords"),
}

OP_LABELS = {
    "A": "Op A · Download carved 1D2 (no unlock)",
    "B": "Op B · Carve from 1D1 + Permanent ROM Unlock",
    "C": "Op C · Patch existing 1D2 with permanent unlock",
    "D": "Op D · Extract 0x30A partial from 1D1",
    "E": "Op E · Basic unlock (jackass25 method)",
    "F": "Op F · Carve 1D2 from 0x227",
    "G": "Op G · Carve from 0x227 + Permanent ROM Unlock",
    "H": "Op H · Extract full 0x30A from 0x227",
}


# ============================================================
# Module analysis (pure functions — no Streamlit dependencies)
# ============================================================
def find_magic(buf: bytes, hint: int = CARVE_OFFSET) -> int:
    if len(buf) >= hint + 4 and buf[hint:hint + 4] == MAGIC:
        return hint
    return buf.find(MAGIC)


def carve_1d2_from_1d1(buf: Optional[bytes]) -> Optional[bytes]:
    if not buf:
        return None
    off = find_magic(buf, CARVE_OFFSET)
    if off < 0 or off + SIZE_1D2 > len(buf):
        return None
    return bytes(buf[off:off + SIZE_1D2])


def carve_1d2_from_227(buf: Optional[bytes]) -> Optional[bytes]:
    if not buf or len(buf) < OFF_1D2_IN_227 + SIZE_1D2:
        return None
    if buf[OFF_1D2_IN_227:OFF_1D2_IN_227 + 4] == MAGIC:
        return bytes(buf[OFF_1D2_IN_227:OFF_1D2_IN_227 + SIZE_1D2])
    off = find_magic(buf, OFF_1D2_IN_227)
    if off < 0 or off + SIZE_1D2 > len(buf):
        return None
    return bytes(buf[off:off + SIZE_1D2])


def carve_30a_from_227(buf: Optional[bytes]) -> Optional[bytes]:
    if not buf or len(buf) < OFF_30A_IN_227 + SIZE_30A_FULL:
        return None
    return bytes(buf[OFF_30A_IN_227:OFF_30A_IN_227 + SIZE_30A_FULL])


def carve_30a_from_1d1(buf: Optional[bytes]) -> Optional[bytes]:
    if not buf or len(buf) < PWD_OFFSET + PWD_LENGTH:
        return None
    return bytes(buf[PWD_OFFSET:PWD_OFFSET + PWD_LENGTH])


def le_sum(buf: bytes, end: int) -> int:
    s = 0
    for i in range(0, end, 2):
        s += buf[i] | (buf[i + 1] << 8)
    return s & 0xFFFF


def checksum_status(buf: bytes):
    if len(buf) < CKSUM_OFFSET + 2:
        return None, None, False
    stored = buf[CKSUM_OFFSET] | (buf[CKSUM_OFFSET + 1] << 8)
    computed = le_sum(buf, CKSUM_OFFSET)
    return stored, computed, stored == computed


def magic_ok(buf: bytes) -> bool:
    return len(buf) >= 4 and bytes(buf[:4]) == MAGIC


def scan_band_ids(buf: bytes) -> list[str]:
    ids = []
    for i in range(16):
        off = 0x100 + i * 0x80 + 0x82
        if off >= len(buf):
            break
        v = buf[off]
        if 1 <= v <= 0xF:
            ids.append(f"0x{v:02X}")
    return ids


def is_body_blank(buf: bytes) -> bool:
    """A 1D2 with the body entirely zeroed out (typical on-drive corruption signature)."""
    start, end = 0x08, 0x1C80
    zeros = sum(1 for i in range(start, end) if buf[i] == 0)
    return zeros >= (end - start) * 0.98


def diagnose(buf: bytes) -> tuple[str, str]:
    """Returns (text, severity_class)."""
    if len(buf) != SIZE_1D2:
        return f"unexpected size {len(buf)} bytes", "bad"
    if not magic_ok(buf):
        return "corrupt header — magic missing", "bad"
    _, _, ck_ok = checksum_status(buf)
    lock = buf[LOCK_OFFSET]
    bands = scan_band_ids(buf)
    if is_body_blank(buf):
        return "BLANKED — body wiped, restore from 1D1/0x227 needed", "bad"
    if not ck_ok:
        return "corrupt — checksum mismatch", "bad"
    if lock == 0x80:
        return f"healthy, LOCKED · {len(bands)} band record(s)", "warn"
    if lock == 0x81:
        return f"healthy, UNLOCKED (permanent) · {len(bands)} band record(s)", "ok"
    return f"unusual lock byte 0x{lock:02X} but structure valid", "info"


def diagnose_health_score(buf: Optional[bytes]) -> float:
    """Higher = healthier. Used to auto-pick the better copy."""
    if not buf or len(buf) != SIZE_1D2:
        return -1
    if not magic_ok(buf):
        return 0
    if is_body_blank(buf):
        return 1
    _, _, ck_ok = checksum_status(buf)
    if not ck_ok:
        return 1.5
    lock = buf[LOCK_OFFSET]
    if lock == 0x81:
        return 4
    if lock == 0x80:
        return 3
    return 2


def lock_display(b: int) -> tuple[str, str]:
    if b == 0x80:
        return "0x80 — LOCKED", "warn"
    if b == 0x81:
        return "0x81 — UNLOCKED (permanent ROM)", "ok"
    if b == 0xFF:
        return "0xFF — uninitialized (blank-1D2 signature)", "info"
    return f"0x{b:02X} — unusual", "info"


def compare_key_region(a: bytes, b: bytes) -> tuple[int, int, int, int]:
    diff = sum(1 for i in range(KEY_REGION_START, KEY_REGION_END) if a[i] != b[i])
    dup_diff = sum(1 for i in range(KEY_DUP_START, KEY_DUP_END) if a[i] != b[i])
    nz_a = sum(1 for i in range(KEY_REGION_START, KEY_REGION_END) if a[i])
    nz_b = sum(1 for i in range(KEY_REGION_START, KEY_REGION_END) if b[i])
    return diff, dup_diff, nz_a, nz_b


def apply_unlock(buf: bytes) -> bytes:
    """Returns a NEW bytes with permanent-ROM-unlock applied (idempotent)."""
    out = bytearray(buf)
    old_lock = out[LOCK_OFFSET]
    if old_lock == 0x81:
        return bytes(out)
    word_off = LOCK_OFFSET & ~1  # 0x04
    old_word = out[word_off] | (out[word_off + 1] << 8)
    out[LOCK_OFFSET] = 0x81
    new_word = out[word_off] | (out[word_off + 1] << 8)
    delta = (new_word - old_word) & 0xFFFF
    ck = out[CKSUM_OFFSET] | (out[CKSUM_OFFSET + 1] << 8)
    ck2 = (ck + delta) & 0xFFFF
    out[CKSUM_OFFSET] = ck2 & 0xFF
    out[CKSUM_OFFSET + 1] = (ck2 >> 8) & 0xFF
    return bytes(out)


# ============================================================
# File classification
# ============================================================
def classify_name(name: str) -> Optional[str]:
    """Return a slot key from a filename, or None if not classifiable by name."""
    n = name.lower()
    # 0x227 / 0x30A first (could substring-match 1d1/1d2 if oddly named)
    if re.search(r'(^|[^a-z0-9])30a([^a-z0-9]|$)', n) or '0x30a' in n:
        return "0x30a"
    if re.search(r'(^|[^a-z0-9])227([^a-z0-9]|$)', n) or '0x227' in n:
        return "0x227"
    mod = '1d1' if '1d1' in n else ('1d2' if '1d2' in n else None)
    if not mod:
        return None
    has_x0 = 'x0' in n
    has_x1 = 'x1' in n
    if has_x0 and not has_x1:
        return mod + 'x0'
    if has_x1 and not has_x0:
        return mod + 'x1'
    return None  # module known, copy unspecified


def classify_and_load(uploaded_files, slots: dict) -> list[tuple[str, str]]:
    """Three-pass classification: precise -> by name -> by size. Mutates slots."""
    msgs: list[tuple[str, str]] = []
    items: list[tuple[str, bytes]] = []

    for f in uploaded_files:
        data = f.getvalue()  # bytes
        name = f.name
        nlow = name.lower()

        # 7z detection
        is_7z = (len(data) >= 6 and data[0] == 0x37 and data[1] == 0x7A
                 and data[2] == 0xBC and data[3] == 0xAF and data[4] == 0x27 and data[5] == 0x1C)
        if nlow.endswith('.7z') or is_7z:
            msgs.append(("error", f"{name} is a 7z archive — extract first or zip the contents."))
            continue

        # ZIP detection (extension or PK magic)
        is_zip = nlow.endswith('.zip') or (
            len(data) >= 4 and data[0] == 0x50 and data[1] == 0x4B and data[2] in (3, 5, 7)
        )
        if is_zip:
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    added = 0
                    for entry in z.namelist():
                        if entry.endswith('/'):
                            continue
                        ln = entry.lower()
                        if (ln.startswith('__macosx/') or ln.endswith('.ds_store')
                                or '/.' in ln):
                            continue
                        edata = z.read(entry)
                        items.append((entry.split('/')[-1], edata))
                        added += 1
                    msgs.append(("info", f"Extracted {added} file(s) from {name}"))
            except Exception as e:
                msgs.append(("error", f"Couldn't read ZIP {name}: {e}"))
            continue

        items.append((name, data))

    consumed = set()

    # Pass 1: precise slot match by name (with x0/x1)
    for i, (name, data) in enumerate(items):
        slot = classify_name(name)
        if slot and slots[slot]['buf'] is None:
            slots[slot]['buf'] = data
            slots[slot]['name'] = name
            msgs.append(("ok", f"Loaded {slot.upper()}: {name} ({fmt_size(len(data))})"))
            consumed.add(i)

    # Pass 2: name implies module, no copy specifier
    for i, (name, data) in enumerate(items):
        if i in consumed:
            continue
        nlow = name.lower()
        mod = '1d1' if '1d1' in nlow else ('1d2' if '1d2' in nlow else None)
        if not mod:
            continue
        cand = (f"{mod}x0" if not slots[f"{mod}x0"]['buf']
                else (f"{mod}x1" if not slots[f"{mod}x1"]['buf'] else None))
        if cand:
            slots[cand]['buf'] = data
            slots[cand]['name'] = name
            msgs.append(("ok", f"Loaded {cand.upper()} (by name): {name}"))
            consumed.add(i)

    # Pass 3: size-only fallback
    for i, (name, data) in enumerate(items):
        if i in consumed:
            continue
        cand = None
        if len(data) == SIZE_1D2:
            cand = ("1d2x0" if not slots["1d2x0"]['buf']
                    else ("1d2x1" if not slots["1d2x1"]['buf'] else None))
        elif len(data) > 0x200000 and not slots["0x227"]['buf']:
            cand = "0x227"
        elif SIZE_1D2 < len(data) <= 0x200000:
            cand = ("1d1x0" if not slots["1d1x0"]['buf']
                    else ("1d1x1" if not slots["1d1x1"]['buf'] else None))
        elif len(data) <= SIZE_30A_FULL and not slots["0x30a"]['buf']:
            cand = "0x30a"
        if cand:
            slots[cand]['buf'] = data
            slots[cand]['name'] = name
            msgs.append(("ok", f"Loaded {cand.upper()} (by size): {name}"))
        else:
            msgs.append(("info", f"Skipped {name} — no matching free slot ({fmt_size(len(data))})"))

    return msgs


def fmt_size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / 1024 / 1024:.2f} MiB"
    if n >= 1024:
        return f"{n / 1024:.1f} KiB"
    return f"{n} B"


# ============================================================
# Active-source selection
# ============================================================
def auto_select_active(slots: dict) -> tuple[str, str]:
    """Pick the healthier copy as default active source for 1D1 and 1D2."""
    if slots["1d1x0"]['buf'] and slots["1d1x1"]['buf']:
        c0 = carve_1d2_from_1d1(slots["1d1x0"]['buf'])
        c1 = carve_1d2_from_1d1(slots["1d1x1"]['buf'])
        active_1d1 = "1d1x1" if diagnose_health_score(c1) > diagnose_health_score(c0) else "1d1x0"
    elif slots["1d1x1"]['buf'] and not slots["1d1x0"]['buf']:
        active_1d1 = "1d1x1"
    else:
        active_1d1 = "1d1x0"

    if slots["1d2x0"]['buf'] and slots["1d2x1"]['buf']:
        s0 = diagnose_health_score(slots["1d2x0"]['buf'])
        s1 = diagnose_health_score(slots["1d2x1"]['buf'])
        active_1d2 = "1d2x1" if s1 > s0 else "1d2x0"
    elif slots["1d2x1"]['buf'] and not slots["1d2x0"]['buf']:
        active_1d2 = "1d2x1"
    else:
        active_1d2 = "1d2x0"

    return active_1d1, active_1d2


def pick_active_1d1_slot(slots: dict, active_1d1: str) -> Optional[str]:
    if slots[active_1d1]['buf']:
        return active_1d1
    alt = "1d1x1" if active_1d1 == "1d1x0" else "1d1x0"
    return alt if slots[alt]['buf'] else None


def pick_active_1d2_slot(slots: dict, active_1d2: str) -> Optional[str]:
    if slots[active_1d2]['buf']:
        return active_1d2
    alt = "1d2x1" if active_1d2 == "1d2x0" else "1d2x0"
    return alt if slots[alt]['buf'] else None


# ============================================================
# Recommendation engine — primary + optional alternate
# ============================================================
def make_recommendations(slots: dict, active_1d1: str, active_1d2: str) -> list[dict]:
    s1d1 = pick_active_1d1_slot(slots, active_1d1)
    s1d2 = pick_active_1d2_slot(slots, active_1d2)
    a1d1 = slots[s1d1]['buf'] if s1d1 else None
    a1d2 = slots[s1d2]['buf'] if s1d2 else None
    a227 = slots["0x227"]['buf']
    a30a = slots["0x30a"]['buf']

    if not (a1d1 or a1d2 or a227 or a30a):
        return []

    carved_from_1d1 = carve_1d2_from_1d1(a1d1) if a1d1 else None
    carved_from_227 = carve_1d2_from_227(a227) if a227 else None

    def carve_pair(label: str, op_a: str, op_b: str) -> list[dict]:
        return [
            {"role": "primary", "op": op_a, "severity": "action",
             "verdict": f"Carve 1D2 from {label} — preserve original lock state",
             "rationale": (
                 f"Safest first step: write back exactly what {label} has stored, without touching "
                 "the lock byte. The drive will come up with whatever lock state was originally "
                 "present in the source. If the drive then works, you're done. If the drive still "
                 "won't accept terminal commands without a handshake, come back and use the "
                 "alternate (permanent ROM unlock) below.")},
            {"role": "alternate", "op": op_b, "severity": "action",
             "verdict": "Or also apply Permanent ROM Unlock",
             "rationale": (
                 "Same carve as the primary, but additionally patches byte 0x04 to 0x81 and fixes "
                 "the checksum so the drive's terminal comes up unlocked at every boot without "
                 "needing a handshake. Use this if the primary doesn't get the drive into a "
                 "workable state, or if you want unlocked-by-default behavior. This does NOT "
                 "change the encrypted ATA passwords in 0x30A.")},
        ]

    # Have a supplied 1D2 to inspect
    if a1d2 and len(a1d2) == SIZE_1D2:
        lock = a1d2[LOCK_OFFSET]
        blank = is_body_blank(a1d2)

        if blank:
            if carved_from_1d1:
                return carve_pair("1D1", "A", "B")
            if carved_from_227:
                return carve_pair("0x227", "F", "G")
            return [{"role": "primary", "op": None, "severity": "info",
                     "verdict": "1D2 is BLANKED — load 1D1 or 0x227 to enable repair",
                     "rationale": "Without a healthy source module loaded, there's no way to reconstruct the keys."}]

        source_carve = carved_from_1d1 or carved_from_227
        if source_carve:
            diff, dup_diff, nz_a, nz_b = compare_key_region(source_carve, a1d2)
            keys_match = (diff == 0 and dup_diff == 0)

            if keys_match:
                if lock == 0x81:
                    return [{"role": "primary", "op": None, "severity": "ok",
                             "verdict": "Drive is healthy and already permanently unlocked — nothing to do",
                             "rationale": "The supplied 1D2's band-key region matches the source, and the lock byte is already 0x81."}]
                if lock == 0x80:
                    return [
                        {"role": "primary", "op": None, "severity": "ok",
                         "verdict": "No action needed — keys are intact and the drive is locked normally",
                         "rationale": "The supplied 1D2's keys match the 1D1/0x227 reference. If the drive currently works, leave it alone. The alternate below is only for cases where you want the drive's terminal to come up without a handshake at every boot."},
                        {"role": "alternate", "op": "C", "severity": "action",
                         "verdict": "Optional: apply Permanent ROM Unlock (Op C)",
                         "rationale": "Patches byte 0x04 from 0x80 to 0x81 and adjusts the checksum, leaving the keys untouched."},
                    ]
                return [{"role": "primary", "op": "C", "severity": "action",
                         "verdict": f"Keys are intact — Op C normalizes the unusual lock byte (0x{lock:02X})",
                         "rationale": "Keys match the source. Op C will set byte 0x04 to 0x81 and fix the checksum."}]

            if nz_b < 100 and nz_a > 100:
                if carved_from_1d1:
                    return carve_pair("1D1", "A", "B")
                if carved_from_227:
                    return carve_pair("0x227", "F", "G")

            return [{"role": "primary", "op": None, "severity": "warn",
                     "verdict": f"Keys differ in {diff} bytes — manual investigation recommended",
                     "rationale": "Inspect both files in a hex editor before overwriting. If you decide to restore from source, Op A (or F) carves it without touching the lock byte; Op B (or G) also applies permanent ROM unlock."}]

        # 1D2 supplied but no source loaded
        if lock == 0x81:
            return [{"role": "primary", "op": None, "severity": "ok",
                     "verdict": "Supplied 1D2 already shows permanent ROM unlock (0x81)",
                     "rationale": "No 1D1/0x227 loaded for cross-check, but the lock byte is already 0x81."}]
        if lock == 0x80:
            return [{"role": "primary", "op": "C", "severity": "action",
                     "verdict": "Apply permanent ROM unlock to the supplied 1D2 (Op C)",
                     "rationale": "Lock byte is 0x80. Op C patches it to 0x81 with checksum fix. No source loaded for verifying the keys are intact — load one if you want to verify before overwriting."}]
        return [{"role": "primary", "op": None, "severity": "info",
                 "verdict": f"Lock byte is 0x{lock:02X} — load 1D1 or 0x227 for diagnosis",
                 "rationale": "Without a source module loaded, the tool can't tell whether the supplied 1D2 is healthy."}]

    # No 1D2 supplied — output a clean 1D2 from source
    if carved_from_1d1:
        return carve_pair("1D1", "A", "B")
    if carved_from_227:
        return carve_pair("0x227", "F", "G")

    if a30a and not a1d1 and not a227 and not a1d2:
        return [{"role": "primary", "op": None, "severity": "info",
                 "verdict": "Only 0x30A loaded — load 1D1, 0x227, or 1D2 to enable repair",
                 "rationale": "0x30A holds the encrypted ATA passwords. Drop in 1D1, 0x227, or 1D2 to enable repair operations."}]

    return []


# ============================================================
# Repair operations — return bytes (or None if not possible)
# ============================================================
def op_a(slots, active_1d1):
    s = pick_active_1d1_slot(slots, active_1d1)
    return carve_1d2_from_1d1(slots[s]['buf']) if s else None


def op_b(slots, active_1d1):
    out = op_a(slots, active_1d1)
    return apply_unlock(out) if out else None


def op_c(slots, active_1d2):
    s = pick_active_1d2_slot(slots, active_1d2)
    buf = slots[s]['buf'] if s else None
    if not buf or len(buf) != SIZE_1D2:
        return None
    return apply_unlock(buf)


def op_d(slots, active_1d1):
    s = pick_active_1d1_slot(slots, active_1d1)
    return carve_30a_from_1d1(slots[s]['buf']) if s else None


def op_e(slots, active_1d1, active_1d2):
    s1 = pick_active_1d1_slot(slots, active_1d1)
    s2 = pick_active_1d2_slot(slots, active_1d2)
    a = slots[s1]['buf'] if s1 else None
    b = slots[s2]['buf'] if s2 else None
    if not a or not b or len(a) < 0x200:
        return None
    out = bytearray(b)
    out[:0x200] = a[:0x200]
    return bytes(out)


def op_f(slots):
    return carve_1d2_from_227(slots["0x227"]['buf']) if slots["0x227"]['buf'] else None


def op_g(slots):
    out = op_f(slots)
    return apply_unlock(out) if out else None


def op_h(slots):
    return carve_30a_from_227(slots["0x227"]['buf']) if slots["0x227"]['buf'] else None


def compute_op_output(op: str, slots: dict, active_1d1: str, active_1d2: str) -> Optional[bytes]:
    return {
        "A": lambda: op_a(slots, active_1d1),
        "B": lambda: op_b(slots, active_1d1),
        "C": lambda: op_c(slots, active_1d2),
        "D": lambda: op_d(slots, active_1d1),
        "E": lambda: op_e(slots, active_1d1, active_1d2),
        "F": lambda: op_f(slots),
        "G": lambda: op_g(slots),
        "H": lambda: op_h(slots),
    }.get(op, lambda: None)()


def base_from(slot_key: Optional[str], slots: dict) -> str:
    if not slot_key or not slots[slot_key]['buf']:
        return "module"
    nm = slots[slot_key]['name']
    return re.sub(r'\.(bin|rpm)$', '', nm, flags=re.IGNORECASE)


def src_tag(slot_key: Optional[str]) -> str:
    return f"_{slot_key.upper()}" if slot_key else ""


def make_filename(op: str, slots: dict, active_1d1: str, active_1d2: str) -> str:
    s1 = pick_active_1d1_slot(slots, active_1d1)
    s2 = pick_active_1d2_slot(slots, active_1d2)
    if op == "A":
        return re.sub(r'1[Dd]1', '1D2', base_from(s1, slots)) + src_tag(s1) + "_carved.Bin"
    if op == "B":
        return re.sub(r'1[Dd]1', '1D2', base_from(s1, slots)) + src_tag(s1) + "_unlocked.Bin"
    if op == "C":
        return base_from(s2, slots) + src_tag(s2) + "_unlocked.Bin"
    if op == "D":
        return re.sub(r'1[Dd]1', '30A_partial', base_from(s1, slots)) + src_tag(s1) + ".Bin"
    if op == "E":
        return base_from(s2, slots) + src_tag(s2) + "_basic_unlock.Bin"
    if op == "F":
        return re.sub(r'0?x?227', '1D2', base_from("0x227", slots), flags=re.IGNORECASE) + "_carved_from_0x227.Bin"
    if op == "G":
        return re.sub(r'0?x?227', '1D2', base_from("0x227", slots), flags=re.IGNORECASE) + "_unlocked_from_0x227.Bin"
    if op == "H":
        return re.sub(r'0?x?227', '30A_full', base_from("0x227", slots), flags=re.IGNORECASE) + "_from_0x227.Bin"
    return "output.Bin"


# ============================================================
# Streamlit rendering helpers
# ============================================================
SEV_BADGE = {"ok": "🟢", "warn": "🟡", "bad": "🔴", "info": "🔵"}


def fmt_capacity(lba: int) -> str:
    if lba <= 0:
        return "n/a"
    bytes_ = lba * 512
    tb = bytes_ / 1e12
    if tb >= 0.5:
        return f"{tb:.2f} TB"
    return f"{bytes_ / 1e9:.1f} GB"


def format_hex(buf: bytes, length: int = 256, start_offset: int = 0) -> str:
    lines = []
    end = min(length, len(buf) - start_offset)
    for i in range(0, end, 16):
        slice_ = buf[start_offset + i: start_offset + i + 16]
        hex_str = ' '.join(f'{b:02X}' for b in slice_)
        ascii_str = ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in slice_)
        lines.append(f"{(start_offset + i):08X}  {hex_str:<48}  {ascii_str}")
    return '\n'.join(lines)


def render_inspection_table(buf: bytes):
    rows = []
    rows.append(("Size", f"{len(buf):,} (0x{len(buf):X})"))
    rows.append(("Magic @ 0x0000",
                 "🟢 OK · `C2 BD 12 0B`" if magic_ok(buf)
                 else "🔴 BAD · `" + ' '.join(f'{b:02X}' for b in buf[:4]) + "`"))
    lock_text, lock_cls = lock_display(buf[LOCK_OFFSET])
    rows.append((f"Lock byte @ 0x{LOCK_OFFSET:04X}", f"{SEV_BADGE[lock_cls]} {lock_text}"))
    stored, computed, ck_ok = checksum_status(buf)
    rows.append((f"Checksum @ 0x{CKSUM_OFFSET:04X}",
                 f"stored `0x{stored:04X}` · computed `0x{computed:04X}` · "
                 + ("🟢 valid" if ck_ok else "🔴 invalid")))
    cap = int.from_bytes(buf[CAP_OFFSET:CAP_OFFSET + 8], 'little')
    rows.append((f"Capacity LBAs @ 0x{CAP_OFFSET:04X}", f"{cap:,} ≈ {fmt_capacity(cap)}"))
    rows.append((f"Sentinel @ 0x{SENT_OFFSET:04X}", f"`0x{buf[SENT_OFFSET]:02X}`"))
    bands = scan_band_ids(buf)
    rows.append(("Band IDs present", ", ".join(bands) if bands else "(none — body wiped or never populated)"))
    diag_text, diag_cls = diagnose(buf)
    rows.append(("**Diagnosis**", f"{SEV_BADGE[diag_cls]} **{diag_text}**"))

    md = "| | |\n|---|---|\n"
    for label, value in rows:
        md += f"| {label} | {value} |\n"
    st.markdown(md)


def render_module_summary(slots: dict, active_1d1_slot: Optional[str],
                          active_1d2_slot: Optional[str]):
    """One row per loaded module — diagnosis at a glance."""
    rows = []

    def add(slot_key, label, buf, diag_text, diag_cls, is_active):
        marker = "● " if is_active else ""
        rows.append({
            "Slot": f"{marker}{label}",
            "Size": fmt_size(len(buf)),
            "Diagnosis": f"{SEV_BADGE[diag_cls]} {diag_text}",
        })

    for k in ["1d1x0", "1d1x1"]:
        if not slots[k]['buf']:
            continue
        inner = carve_1d2_from_1d1(slots[k]['buf'])
        if inner:
            txt, cls = diagnose(inner)
        else:
            txt, cls = "no C2BD120B magic at 0x22000", "bad"
        copy_label = "copy 0" if k.endswith("x0") else "copy 1"
        add(k, f"1D1 {copy_label} (inner 1D2)", slots[k]['buf'], txt, cls, active_1d1_slot == k)

    for k in ["1d2x0", "1d2x1"]:
        if not slots[k]['buf']:
            continue
        txt, cls = diagnose(slots[k]['buf'])
        copy_label = "copy 0" if k.endswith("x0") else "copy 1"
        add(k, f"1D2 {copy_label}", slots[k]['buf'], txt, cls, active_1d2_slot == k)

    if slots["0x227"]['buf']:
        inner = carve_1d2_from_227(slots["0x227"]['buf'])
        if inner:
            txt, cls = diagnose(inner)
        else:
            txt, cls = "no C2BD120B magic at 0x1C5000", "warn"
        add("0x227", "0x227 (inner 1D2)", slots["0x227"]['buf'], txt, cls, False)

    if slots["0x30a"]['buf']:
        buf = slots["0x30a"]['buf']
        if len(buf) == SIZE_30A_FULL:
            txt, cls = "full 0x30A passwords module (4 KiB)", "info"
        elif len(buf) == PWD_LENGTH:
            txt, cls = "partial 0x30A from 1D1 (272 B)", "info"
        else:
            txt, cls = f"non-standard 0x30A ({len(buf)} B)", "warn"
        add("0x30a", "0x30A", buf, txt, cls, False)

    if rows:
        st.markdown("**Loaded modules at a glance** &nbsp;&nbsp;<small>● = active source</small>",
                    unsafe_allow_html=True)
        st.dataframe(rows, hide_index=True, use_container_width=True)


def render_key_match(carved: bytes, supplied: bytes):
    diff, dup_diff, nz_a, nz_b = compare_key_region(carved, supplied)
    if diff == 0 and dup_diff == 0:
        st.success(
            "**Encryption keys are intact — no key restore needed.** "
            "The band-key region (0x100–0x900) and its duplicate (0x980–0x1180) are byte-identical "
            "between the supplied 1D2 and the carved-from-source 1D2. The drive's per-band AES keys "
            "have not been damaged. If you only want to flip the lock state, Op C is sufficient. "
            "If everything already works, nothing needs to be done."
        )
    elif nz_b < 100 and nz_a > 100:
        st.warning(
            f"**Keys missing in supplied 1D2 — restore from source needed.** "
            f"The supplied 1D2 has the band-key region effectively blanked "
            f"(only {nz_b} non-zero bytes out of {KEY_REGION_END - KEY_REGION_START}). "
            f"The carved-from-source 1D2 has {nz_a} non-zero bytes there. "
            f"Use **Op B** (1D1) or **Op G** (0x227) to restore the keys + permanent unlock in one step."
        )
    else:
        st.error(
            f"**Keys differ in {diff} byte(s) — manual investigation recommended.** "
            f"Neither side is fully blanked, but {diff} bytes differ in the main key region and "
            f"{dup_diff} bytes differ in the duplicate. Supplied has {nz_b} non-zero bytes; "
            f"carved has {nz_a}. This is unusual — inspect both files before overwriting."
        )


def render_recommendation(reco: dict, slots: dict, active_1d1: str, active_1d2: str,
                          is_primary: bool, key_suffix: str):
    sev = reco['severity']
    role_label = "Recommended action" if is_primary else "Alternate (use only if primary doesn't work)"
    if sev == "ok":
        role_label = "No action needed" if is_primary else "Optional"

    title_md = f"**{role_label}: {reco['verdict']}**\n\n{reco['rationale']}"
    if sev == "ok":
        st.success(title_md)
    elif sev == "warn":
        st.warning(title_md)
    elif sev == "info":
        st.info(title_md)
    else:
        st.info(title_md)

    if reco['op']:
        data = compute_op_output(reco['op'], slots, active_1d1, active_1d2)
        if data:
            filename = make_filename(reco['op'], slots, active_1d1, active_1d2)
            st.download_button(
                label=f"⬇ {OP_LABELS[reco['op']]}",
                data=data,
                file_name=filename,
                mime="application/octet-stream",
                type="primary" if is_primary else "secondary",
                key=f"reco_{key_suffix}_{reco['op']}",
            )


def render_op_card(op_letter: str, title: str, desc: str, slots: dict,
                   active_1d1: str, active_1d2: str, badge: str = ""):
    """Detailed op card for the lower section."""
    data = compute_op_output(op_letter, slots, active_1d1, active_1d2)
    enabled = data is not None
    with st.container(border=True):
        cols = st.columns([5, 2])
        with cols[0]:
            st.markdown(f"**{op_letter} · {title}** {badge}")
            st.caption(desc)
        with cols[1]:
            if enabled:
                st.download_button(
                    label="Download",
                    data=data,
                    file_name=make_filename(op_letter, slots, active_1d1, active_1d2),
                    mime="application/octet-stream",
                    key=f"op_{op_letter}",
                    use_container_width=True,
                )
            else:
                st.button("Download", disabled=True, key=f"op_dis_{op_letter}",
                          use_container_width=True)


def render_cross_checks(slots: dict, active_1d1: str, active_1d2: str):
    rows = []

    def cmp(label, a, b):
        if not a or not b:
            return
        if len(a) != len(b):
            rows.append({"Comparison": label, "Result": f"🔴 size mismatch ({len(a)} vs {len(b)})"})
            return
        diff = 0
        for i in range(len(a)):
            if a[i] != b[i]:
                diff += 1
                if diff > 1000:
                    break
        if diff == 0:
            rows.append({"Comparison": label, "Result": "🟢 identical"})
        else:
            txt = f">{1000}" if diff > 1000 else f"{diff}"
            rows.append({"Comparison": label, "Result": f"🟡 {txt} byte(s) differ"})

    cmp("1D1 copy 0  ↔  1D1 copy 1", slots["1d1x0"]['buf'], slots["1d1x1"]['buf'])
    cmp("1D2 copy 0  ↔  1D2 copy 1", slots["1d2x0"]['buf'], slots["1d2x1"]['buf'])

    if slots["1d1x0"]['buf'] and slots["1d1x1"]['buf']:
        a = carve_1d2_from_1d1(slots["1d1x0"]['buf'])
        b = carve_1d2_from_1d1(slots["1d1x1"]['buf'])
        cmp("Inner 1D2 carved from 1D1×0  ↔  from 1D1×1", a, b)

    s1d1_slot = pick_active_1d1_slot(slots, active_1d1)
    a1d1 = slots[s1d1_slot]['buf'] if s1d1_slot else None
    a227 = slots["0x227"]['buf']
    if a1d1 and a227:
        a = carve_1d2_from_1d1(a1d1)
        b = carve_1d2_from_227(a227)
        cmp("1D2 carved from 1D1  ↔  1D2 carved from 0x227", a, b)
        partial = carve_30a_from_1d1(a1d1)
        full = carve_30a_from_227(a227)
        if partial and full:
            cmp("0x30A partial from 1D1  ↔  first 0x110 of 0x30A from 0x227",
                partial, full[:PWD_LENGTH])

    a30a = slots["0x30a"]['buf']
    if a30a and a227:
        full = carve_30a_from_227(a227)
        if full and len(a30a) == len(full):
            cmp("Supplied 0x30A  ↔  0x30A carved from 0x227", a30a, full)
        elif a30a and a1d1 and len(a30a) == PWD_LENGTH:
            partial = carve_30a_from_1d1(a1d1)
            if partial:
                cmp("Supplied 0x30A (partial)  ↔  partial from 1D1", a30a, partial)

    if rows:
        st.markdown("**Cross-checks between modules & copies**")
        st.dataframe(rows, hide_index=True, use_container_width=True)


def render_227_card(buf: bytes, name: str):
    with st.container(border=True):
        st.markdown(f"**0x227 container** · *{name}*")
        rows = []
        rows.append(("Size", f"{len(buf):,} (0x{len(buf):X})"))
        if len(buf) >= OFF_1D2_IN_227 + 4:
            ok = buf[OFF_1D2_IN_227:OFF_1D2_IN_227 + 4] == MAGIC
            mag = ("🟢 OK · `C2 BD 12 0B`" if ok
                   else "🔴 BAD · `" + ' '.join(f'{b:02X}' for b in buf[OFF_1D2_IN_227:OFF_1D2_IN_227 + 4]) + "`")
        else:
            mag = "🟡 file too small to contain 1D2"
        rows.append((f"Embedded 1D2 magic @ 0x{OFF_1D2_IN_227:08X}", mag))
        if len(buf) >= OFF_30A_IN_227 + 16:
            slice_ = buf[OFF_30A_IN_227:OFF_30A_IN_227 + 16]
            r30a = "first 16 B: `" + ' '.join(f'{b:02X}' for b in slice_) + "`"
        else:
            r30a = "🟡 file too small to contain 0x30A"
        rows.append((f"Embedded 0x30A region @ 0x{OFF_30A_IN_227:08X}", r30a))
        inner = carve_1d2_from_227(buf)
        if inner:
            txt, cls = diagnose(inner)
            rows.append(("Embedded 1D2 diagnosis", f"{SEV_BADGE[cls]} {txt}"))
        md = "| | |\n|---|---|\n" + "".join(f"| {l} | {v} |\n" for l, v in rows)
        st.markdown(md)
        with st.expander("Hex (first 256 bytes)"):
            st.code(format_hex(buf, 256, 0), language="text")
        if len(buf) >= OFF_1D2_IN_227 + 256:
            with st.expander(f"Hex around embedded 1D2 @ 0x{OFF_1D2_IN_227:X} (first 256 bytes)"):
                st.code(format_hex(buf, 256, OFF_1D2_IN_227), language="text")
        if len(buf) >= OFF_30A_IN_227 + 256:
            with st.expander(f"Hex around embedded 0x30A @ 0x{OFF_30A_IN_227:X} (first 256 bytes)"):
                st.code(format_hex(buf, 256, OFF_30A_IN_227), language="text")


def render_30a_card(buf: bytes, name: str):
    with st.container(border=True):
        st.markdown(f"**0x30A passwords** · *{name}*")
        rows = []
        rows.append(("Size", f"{len(buf):,} (0x{len(buf):X})"))
        if len(buf) == SIZE_30A_FULL:
            kind = "matches full (0x30A carved from 0x227)"
        elif len(buf) == PWD_LENGTH:
            kind = "matches partial (0x30A carved from 1D1)"
        elif len(buf) < SIZE_30A_FULL:
            kind = f"partial / non-standard ({len(buf)} bytes)"
        else:
            kind = f"larger than expected ({len(buf)} bytes)"
        rows.append(("Layout match", kind))
        if len(buf) >= 0x180:
            master_nz = sum(1 for i in range(0x60, 0xD0) if buf[i])
            user_nz = sum(1 for i in range(0xF0, 0x170) if buf[i])
            rows.append(("Master pwd region (0x60–0xD0)",
                         f"🟡 data present · {master_nz} non-zero" if master_nz > 0 else "🔵 empty"))
            rows.append(("User pwd region (0xF0–0x170)",
                         f"🟡 data present · {user_nz} non-zero" if user_nz > 0 else "🔵 empty"))
        md = "| | |\n|---|---|\n" + "".join(f"| {l} | {v} |\n" for l, v in rows)
        st.markdown(md)
        with st.expander("Hex (first 256 bytes)"):
            st.code(format_hex(buf, 256, 0), language="text")


# ============================================================
# Main app
# ============================================================
REFERENCE_MD = """
**Header magic (1D2)** — `C2 BD 12 0B` at offset `0x0000`. Search inside source if not at the expected offset.

**Lock-state byte** — Offset `0x04`: `0x80` = locked · `0x81` = permanent ROM unlock.
In a *blanked* on-drive 1D2 this byte is typically `0xFF` with a fully-zeroed body — that's the corruption signature
that calls for restore from 1D1 or 0x227.

**Permanent ROM unlock** — Per HDD Guru forums: setting byte `0x04` to `0x81` (with checksum fix) prevents
the drive's terminal from requiring a handshake at boot. **It is not ATA-password unlock.** ATA passwords
are stored separately in 0x30A as encrypted blobs (and the encryption is salted per-drive, so swapping
0x30A between donors does not transfer the password).

**Band-key region** — 16 × 128-byte records at `0x100 – 0x900` (each = 96-byte AES key + band-ID 0x01..0x0F + 0xFFFF terminator)
with a redundant copy at `0x980 – 0x1180`.
If this region matches between the supplied 1D2 and the carved-from-1D1 1D2, the on-drive keys are intact —
no restore required, only optional unlock.

**Capacity (LBAs)** — Offset `0x1C20`, little-endian uint64. E.g. `0x74710000` ≈ 1 TB,
`0xE8E088B0` = 2 TB, `0x1D1C0BEB0` = 4 TB.

**Sentinel byte at 0x1BE0** — Per-drive sentinel: `0x01` on 1 TB samples, `0xE1` on 2 TB / 4 TB samples
observed by fzabkar.

**Checksum** — Little-endian 16-bit word at offset `0x1C88` equals `(Σ uint16-LE words from 0x00 to 0x1C88) & 0xFFFF`.
Increment by 1 when you flip `0x80 → 0x81` at offset `0x04`.

**Carving offsets**
- `0x1D2` from `0x1D1` at `0x22000 – 0x38FFF`
- `0x1D2` from `0x227` at `0x1C5000 – 0x1DBFFF`
- `0x30A` from `0x227` at `0x2F1000 – 0x2F1FFF` (full 4 KB)
- `0x30A` partial from `0x1D1` at `0x39000 – 0x3910F` (0x110 bytes)

**Redundant copies** — Seagate SA stores each module twice (copy 0 and copy 1). Per fzabkar workflow:
verify `1D1×0 == 1D1×1` before trusting either as a repair source.

**References** — See README for forum links and history.
"""


def init_state():
    if 'slots' not in st.session_state:
        st.session_state.slots = {k: {'buf': None, 'name': ''} for k in SLOT_KEYS}
    if 'active_1d1' not in st.session_state:
        st.session_state.active_1d1 = '1d1x0'
    if 'active_1d2' not in st.session_state:
        st.session_state.active_1d2 = '1d2x0'
    if 'last_upload_sig' not in st.session_state:
        st.session_state.last_upload_sig = None
    if 'last_msgs' not in st.session_state:
        st.session_state.last_msgs = []


def main():
    st.set_page_config(
        page_title="$300 Data Recovery — 1D1 Repair & Unlock",
        layout="wide",
        page_icon="🔧",
    )
    if not check_password():
        return
    init_state()
    slots = st.session_state.slots

    st.title("$300 Data Recovery — 1D1 Repair & Unlock")
    st.caption(
        "Seagate Rosewood / M11 / SED · 1D2 reconstruction, key-match diagnostic, "
        "permanent ROM unlock, 0x227 & 0x30A carving"
    )

    # ============ 1. INPUT ============
    st.subheader("1 · Input modules")
    uploaded = st.file_uploader(
        "Drop module dumps here · accepts up to six files (1D1×0/×1, 1D2×0/×1, 0x227, 0x30A) "
        "or a single ZIP archive containing them",
        type=None,
        accept_multiple_files=True,
        help="Auto-classified by name (1d1/1d2/227/30a + x0/x1) and size.",
    )

    # Auto-load when the uploader's content changes
    if uploaded:
        sig = tuple((f.name, f.size) for f in uploaded)
        if st.session_state.last_upload_sig != sig:
            msgs = classify_and_load(uploaded, slots)
            a1, a2 = auto_select_active(slots)
            st.session_state.active_1d1 = a1
            st.session_state.active_1d2 = a2
            st.session_state.last_upload_sig = sig
            st.session_state.last_msgs = msgs

    for level, msg in st.session_state.last_msgs:
        if level == "error":
            st.error(msg)
        elif level == "ok":
            st.success(msg)
        else:
            st.info(msg)

    # Slot grid (3 rows × 2 cols)
    rows_layout = [("1d1x0", "1d1x1"), ("1d2x0", "1d2x1"), ("0x227", "0x30a")]
    for left, right in rows_layout:
        cols = st.columns(2)
        for col, key in zip(cols, (left, right)):
            with col:
                kind, copy = SLOT_LABELS[key]
                if slots[key]['buf']:
                    with st.container(border=True):
                        st.markdown(f"**{kind} · {copy}**")
                        st.code(
                            f"{slots[key]['name']}\n{len(slots[key]['buf']):,} bytes "
                            f"(0x{len(slots[key]['buf']):X})",
                            language="text",
                        )
                        if st.button(f"Clear", key=f"clear_{key}"):
                            slots[key]['buf'] = None
                            slots[key]['name'] = ''
                            st.rerun()
                else:
                    with st.container(border=True):
                        st.markdown(f"**{kind} · {copy}**")
                        st.caption("*no file loaded*")

    # If nothing loaded, stop here
    if not any(s['buf'] for s in slots.values()):
        st.info("Drop module dumps above to begin.")
        with st.expander("4 · Reference (1D2 structure)"):
            st.markdown(REFERENCE_MD)
        return

    active_1d1 = st.session_state.active_1d1
    active_1d2 = st.session_state.active_1d2

    # ============ 2. INSPECTION ============
    st.subheader("2 · Inspection")

    a_1d1_slot = pick_active_1d1_slot(slots, active_1d1)
    a_1d2_slot = pick_active_1d2_slot(slots, active_1d2)

    render_module_summary(slots, a_1d1_slot, a_1d2_slot)

    # Active source pickers (shown only if both copies of a side are loaded)
    pick_cols = st.columns(2)
    with pick_cols[0]:
        if slots["1d1x0"]['buf'] and slots["1d1x1"]['buf']:
            choice = st.radio(
                "1D1 source",
                ["copy 0", "copy 1"],
                index=0 if active_1d1 == "1d1x0" else 1,
                horizontal=True,
                key="pick_1d1",
            )
            new_active = "1d1x0" if choice == "copy 0" else "1d1x1"
            if new_active != active_1d1:
                st.session_state.active_1d1 = new_active
                st.rerun()
    with pick_cols[1]:
        if slots["1d2x0"]['buf'] and slots["1d2x1"]['buf']:
            choice = st.radio(
                "1D2 source",
                ["copy 0", "copy 1"],
                index=0 if active_1d2 == "1d2x0" else 1,
                horizontal=True,
                key="pick_1d2",
            )
            new_active = "1d2x0" if choice == "copy 0" else "1d2x1"
            if new_active != active_1d2:
                st.session_state.active_1d2 = new_active
                st.rerun()

    a_1d1 = slots[a_1d1_slot]['buf'] if a_1d1_slot else None
    a_1d2 = slots[a_1d2_slot]['buf'] if a_1d2_slot else None
    a_227 = slots["0x227"]['buf']

    # Compute carved candidate (prefer 1D1, fall back to 0x227)
    carved = None
    carved_source = None
    if a_1d1:
        carved = carve_1d2_from_1d1(a_1d1)
        if carved is not None:
            carved_source = a_1d1_slot
    if carved is None and a_227:
        carved = carve_1d2_from_227(a_227)
        if carved is not None:
            carved_source = "0x227"

    cols = st.columns(2)
    with cols[0]:
        if carved is not None:
            st.markdown(f"**Carved candidate** · *from {carved_source.upper()}*")
            render_inspection_table(carved)
            with st.expander("Hex (first 256 bytes)"):
                st.code(format_hex(carved, 256), language="text")
        elif a_1d1 or a_227:
            st.warning("Magic `C2BD120B` not found in source")
    with cols[1]:
        if a_1d2 is not None:
            st.markdown(f"**Existing 1D2** · *{a_1d2_slot.upper()}*")
            render_inspection_table(a_1d2)
            with st.expander("Hex (first 256 bytes)"):
                st.code(format_hex(a_1d2, 256), language="text")

    # Key match diagnostic + full-file diff
    if carved is not None and a_1d2 is not None and len(a_1d2) == SIZE_1D2:
        st.markdown("##### Key-region match diagnostic")
        render_key_match(carved, a_1d2)

        diffs = [i for i in range(min(len(carved), len(a_1d2))) if carved[i] != a_1d2[i]]
        if diffs:
            with st.expander(
                f"Full-file differences (carved vs existing 1D2) — {len(diffs)} byte(s) differ"
            ):
                show = diffs[:30]
                lines = [
                    f"0x{o:04X}  carved=0x{carved[o]:02X}  supplied=0x{a_1d2[o]:02X}"
                    for o in show
                ]
                if len(diffs) > 30:
                    lines.append(f"... and {len(diffs) - 30} more")
                st.code("\n".join(lines), language="text")
        else:
            st.success("Carved 1D2 is byte-identical to the supplied 1D2.")

    # 0x227 / 0x30A inspection cards
    if slots["0x227"]['buf']:
        render_227_card(slots["0x227"]['buf'], slots["0x227"]['name'])
    if slots["0x30a"]['buf']:
        render_30a_card(slots["0x30a"]['buf'], slots["0x30a"]['name'])

    # Cross-checks
    render_cross_checks(slots, active_1d1, active_1d2)

    # ============ 3. REPAIR ============
    st.subheader("3 · Repair operations")

    # Recommendations panel
    recos = make_recommendations(slots, active_1d1, active_1d2)
    if recos:
        for i, r in enumerate(recos):
            render_recommendation(
                r, slots, active_1d1, active_1d2,
                is_primary=(r['role'] == "primary"),
                key_suffix=f"{i}_{r['role']}",
            )
    else:
        st.info("No recommendation — load 1D1, 1D2, or 0x227 to enable repair operations.")

    st.divider()
    st.markdown("##### All repair operations")
    st.caption(
        "Detailed list of all eight repair ops. The recommendation above maps to whichever of these "
        "is the right call for your current state; these are here for advanced/manual cases."
    )

    render_op_card("A", "Carve 1D2 from 1D1 — preserve original lock state",
                   "Extracts 0x2000 bytes starting at the C2BD120B magic inside the active 1D1 "
                   "(normally at offset 0x22000). Writes back what the drive itself stored. Use when "
                   "the on-drive 1D2 is corrupt but the embedded copy in 1D1 is intact and you don't "
                   "need to change the lock state.",
                   slots, active_1d1, active_1d2)
    render_op_card("B", "Carve 1D2 from 1D1 + Permanent ROM Unlock",
                   "Same as A, then patches byte 0x04 from 0x80 → 0x81 and increments the checksum "
                   "word at 0x1C88 by 1. Permanent ROM unlock without sending handshake — the drive's "
                   "terminal comes up unlocked at every power-on, no manual handshake needed. "
                   "This is NOT ATA-password unlock; the encrypted user/master passwords in 0x30A "
                   "are unaffected.",
                   slots, active_1d1, active_1d2, badge="🔵 commonly used")
    render_op_card("C", "Permanent ROM unlock — patch existing 1D2 (no carve)",
                   "Takes the active existing 1D2 as-is, sets byte 0x04 to 0x81 and adjusts the checksum. "
                   "Use when the supplied 1D2's keys are already intact and you only want the unlock "
                   "flag flipped.",
                   slots, active_1d1, active_1d2)
    render_op_card("D", "Extract ATA passwords from 1D1 (partial)",
                   "Carves the 0x110-byte region from the active 1D1 at 0x39000 – 0x3910F. "
                   "This is the partial 0x30A blob embedded inside 1D1. The full 4 KB 0x30A lives in 0x227 — "
                   "use Op H instead if you have 0x227.",
                   slots, active_1d1, active_1d2, badge="🔵 partial")
    render_op_card("E", "Basic unlock (jackass25 method)",
                   "Copies the first 0x200 bytes of the active 1D1 over the first 0x200 bytes of the "
                   "active 1D2. Does NOT produce a valid C2BD120B header; included for completeness only. "
                   "Try A or B first.",
                   slots, active_1d1, active_1d2, badge="🟡 experimental")
    render_op_card("F", "Carve 1D2 from 0x227",
                   "Extracts 0x2000 bytes from the 0x227 container at offset 0x1C5000. Useful when 1D1 "
                   "is missing or damaged but 0x227 is healthy. Preserves the original lock state.",
                   slots, active_1d1, active_1d2)
    render_op_card("G", "Carve 1D2 from 0x227 + Permanent ROM Unlock",
                   "Same as F, then applies the permanent-ROM-unlock patch.",
                   slots, active_1d1, active_1d2)
    render_op_card("H", "Carve full 0x30A from 0x227",
                   "Extracts 0x1000 bytes (4 KB) from the 0x227 container at offset 0x2F1000. "
                   "This is the full passwords module, including the master + user ATA password regions. "
                   "Compare against the partial Op D output (only the first 0x110 bytes).",
                   slots, active_1d1, active_1d2, badge="🔵 complete")

    # ============ 4. REFERENCE ============
    with st.expander("4 · Reference (1D2 structure)"):
        st.markdown(REFERENCE_MD)


if __name__ == "__main__":
    main()
