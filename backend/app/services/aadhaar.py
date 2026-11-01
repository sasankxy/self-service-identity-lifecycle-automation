"""Aadhaar card verification from an uploaded image. Everything runs locally: no card data reaches an external API or any LLM.

  1. Secure QR  decoded with OpenCV; its RSA signature is checked against UIDAI's certificate (AADHAAR_UIDAI_CERT_PATH). This is the
                only step that proves authenticity: a printed card image alone can be edited by anyone.
  2. OCR        RapidOCR reads the printed name, date of birth, gender and number; the number must pass the Verhoeff checksum.
  3. Cross-checks  printed text vs signed QR data, and both vs the onboarding record.

Verdict: verified (valid signature and matching record) | review (a person must look) | failed (a check positively failed).

The image and the full number exist only in memory during the call. `Outcome` holds what may be stored: masked number, keyed hash for
duplicate detection, and per-check results. Do not log or persist raw fields. A successful result proves that a genuine card matches
the record, not that the uploader is its holder; that needs UIDAI OTP/face authentication through a licensed provider.
"""
from __future__ import annotations

import gzip
import hashlib
import hmac
import logging
import re
from dataclasses import dataclass, field
from datetime import date
from difflib import SequenceMatcher
from pathlib import Path

log = logging.getLogger("identityos.aadhaar")

MAX_IMAGE_BYTES = 5 * 1024 * 1024
NAME_MATCH, NAME_REVIEW = 0.85, 0.6
SIGNATURE_LEN = 256

_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
      [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1], [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
      [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
      [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1], [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]

_NUMBER_RE = re.compile(r"(?<!\d)(\d{4})[ -]?(\d{4})[ -]?(\d{4})(?!\d)")
_DOB_RE = re.compile(r"(\d{2})[/-](\d{2})[/-](\d{4})")
_YOB_RE = re.compile(r"(?:year of birth|yob)\D{0,5}(\d{4})", re.IGNORECASE)
_GENDER_RE = re.compile(r"\b(female|male|transgender)\b", re.IGNORECASE)
_NOISE_RE = re.compile(r"government|india|aadhaar|unique|authority|dob|birth|male|female|address|vid|\d", re.IGNORECASE)


def verhoeff_valid(number: str) -> bool:
    if not re.fullmatch(r"[2-9]\d{11}", number):        # Aadhaar numbers never start with 0 or 1
        return False
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


@dataclass
class CardData:
    name: str | None = None
    dob: str | None = None           # DD-MM-YYYY, or YYYY when only the year is known
    gender: str | None = None        # M | F | T
    last4: str | None = None
    number: str | None = None        # full number from OCR; memory only


def _norm_dob(v: str | None) -> str | None:
    if not v:
        return None
    v = v.strip().replace("/", "-")
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", v)
    if m:
        return f"{m[3]}-{m[2]}-{m[1]}"
    return v if re.fullmatch(r"\d{2}-\d{2}-\d{4}|\d{4}", v) else None


def _norm_gender(v: str | None) -> str | None:
    return {"m": "M", "male": "M", "f": "F", "female": "F", "t": "T", "transgender": "T"}.get((v or "").strip().lower())


# ─────────────────────────── secure QR
@dataclass
class QrResult:
    present: bool = False
    parsed: bool = False
    signature: str = "absent"        # valid | invalid | unverified (no certificate configured) | absent
    data: CardData = field(default_factory=CardData)


def parse_secure_qr(raw: str, certificate_pem: bytes | None = None) -> QrResult:
    """UIDAI secure QR: a decimal big integer -> GZIP -> fields separated by 0xFF, followed by a 256-byte RSA-SHA256 signature."""
    out = QrResult(present=True)
    try:
        n = int(raw.strip())
        data = gzip.decompress(n.to_bytes((n.bit_length() + 7) // 8, "big"))
        body, signature = data[:-SIGNATURE_LEN], data[-SIGNATURE_LEN:]
        parts = body.split(b"\xff")
        offset = 1 if parts[0][:1] == b"V" else 0        # V2+ QR codes start with a version field
        f = [p.decode("iso-8859-1") for p in parts[offset:offset + 5]]
        out.data = CardData(name=f[2].strip() or None, dob=_norm_dob(f[3]), gender=_norm_gender(f[4]), last4=f[1][:4] if f[1][:4].isdigit() else None)
        out.parsed = True
    except (ValueError, OSError, EOFError, IndexError, OverflowError):
        return out
    if not certificate_pem:
        out.signature = "unverified"
        return out
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    try:
        x509.load_pem_x509_certificate(certificate_pem).public_key().verify(signature, body, padding.PKCS1v15(), hashes.SHA256())
        out.signature = "valid"
    except InvalidSignature:
        out.signature = "invalid"
    return out


# ─────────────────────────── OCR text
def parse_ocr_lines(lines: list[str]) -> CardData:
    text = "\n".join(lines)
    d = CardData()
    m = _NUMBER_RE.search(text)
    if m:
        d.number = m[1] + m[2] + m[3]
        d.last4 = m[3]
    m = _DOB_RE.search(text)
    if m:
        d.dob = f"{m[1]}-{m[2]}-{m[3]}"
    else:
        m = _YOB_RE.search(text)
        d.dob = m[1] if m else None
    m = _GENDER_RE.search(text)
    d.gender = _norm_gender(m[1]) if m else None
    # the name is the Latin-script line printed just above the date of birth
    idx = next((i for i, l in enumerate(lines) if _DOB_RE.search(l) or _YOB_RE.search(l)), None)
    for line in reversed(lines[:idx] if idx is not None else []):
        clean = line.strip()
        if re.fullmatch(r"[A-Za-z][A-Za-z .']{2,79}", clean) and not _NOISE_RE.search(clean):
            d.name = clean
            break
    return d


def read_image(image_bytes: bytes) -> tuple[str | None, list[str] | None]:
    """(raw QR payload, OCR lines). OCR lines are None if the OCR engine is unavailable."""
    import cv2
    import numpy as np
    img = cv2.imdecode(np.frombuffer(image_bytes, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("not an image")
    qr, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
    try:
        result, _ = _ocr()(img)
        lines = [r[1] for r in result or []]
    except Exception:  # noqa: BLE001 - OCR is one signal among several; never include card content in logs
        log.warning("Aadhaar OCR unavailable")
        lines = None
    return qr or None, lines


_engine = None


def _ocr():
    global _engine
    if _engine is None:
        from rapidocr_onnxruntime import RapidOCR
        _engine = RapidOCR()
    return _engine


# ─────────────────────────── cross-checks and verdict
def name_similarity(a: str | None, b: str | None) -> float:
    def toks(s):
        return sorted(re.findall(r"[a-z]+", (s or "").lower()))
    x, y = toks(a), toks(b)
    if not x or not y:
        return 0.0
    full = SequenceMatcher(None, " ".join(x), " ".join(y)).ratio()
    short, long_ = (x, y) if len(x) <= len(y) else (y, x)          # "Aditya R" vs "Aditya Ramesh": initials count
    subset = all(any(l == s or (len(s) == 1 and l.startswith(s)) for l in long_) for s in short)
    return max(full, 0.9 if subset else 0.0)


def dob_matches(card: str | None, expected: date | None) -> bool | None:
    if not card or not expected:
        return None
    return card == str(expected.year) if len(card) == 4 else card == expected.strftime("%d-%m-%Y")


@dataclass
class Outcome:
    status: str                       # verified | review | failed
    checks: dict                      # name -> {"result": pass|fail|warn|skip, "detail": ...}; contains no raw card data
    masked: str | None = None         # XXXX XXXX 1234
    number_hash: str | None = None


def evaluate(qr: QrResult | None, ocr: CardData | None, *, expected_name: str, expected_dob: date | None = None,
             expected_gender: str | None = None, hash_key: bytes = b"") -> Outcome:
    checks: dict = {}

    def add(name, result, detail):
        checks[name] = {"result": result, "detail": detail}

    if qr is None or not qr.present:
        add("secure_qr", "warn", "No readable QR code, so authenticity could not be checked.")
    elif not qr.parsed:
        add("secure_qr", "warn", "The QR code is not a UIDAI secure QR.")
    elif qr.signature == "valid":
        add("secure_qr", "pass", "UIDAI digital signature is valid.")
    elif qr.signature == "invalid":
        add("secure_qr", "fail", "The QR signature is invalid: the data was altered or not issued by UIDAI.")
    else:
        add("secure_qr", "warn", "QR decoded, but no UIDAI certificate is configured to verify its signature.")

    number = ocr.number if ocr else None
    if ocr is None:
        add("ocr", "warn", "The printed text could not be read.")
    if number:
        add("number_checksum", "pass" if verhoeff_valid(number) else "fail",
            "Aadhaar checksum is valid." if verhoeff_valid(number) else "The printed number fails the Aadhaar checksum.")
    else:
        add("number_checksum", "skip", "No full number could be read from the card.")

    trusted = qr.data if qr and qr.parsed else CardData()
    if qr and qr.parsed and ocr:                  # printed text must agree with the signed data
        diffs = [lbl for lbl, a, b in (("last 4 digits", trusted.last4, ocr.last4), ("date of birth", trusted.dob, ocr.dob),
                                       ("gender", trusted.gender, ocr.gender)) if a and b and a != b]
        if trusted.name and ocr.name and name_similarity(trusted.name, ocr.name) < NAME_REVIEW:
            diffs.append("name")
        add("print_vs_qr", "fail" if diffs else "pass",
            f"Printed {', '.join(diffs)} differ(s) from the signed QR data." if diffs else "Printed details match the QR data.")

    name = trusted.name or (ocr.name if ocr else None)
    dob = trusted.dob or (ocr.dob if ocr else None)
    gender = trusted.gender or (ocr.gender if ocr else None)
    last4 = trusted.last4 or (ocr.last4 if ocr else None)
    score = name_similarity(name, expected_name)
    if not name:
        add("name_match", "warn", "No name could be read from the card.")
    else:
        add("name_match", "pass" if score >= NAME_MATCH else "warn" if score >= NAME_REVIEW else "fail",
            f"Name similarity to the onboarding record: {round(score * 100)}%.")
    dm = dob_matches(dob, expected_dob)
    add("dob_match", "skip" if dm is None else "pass" if dm else "fail",
        "No date of birth to compare." if dm is None else "Date of birth matches." if dm else "Date of birth differs from the onboarding record.")
    if gender and expected_gender:
        ok = gender == _norm_gender(expected_gender)
        add("gender_match", "pass" if ok else "fail", "Gender matches." if ok else "Gender differs from the onboarding record.")

    results = {c["result"] for c in checks.values()}
    required_pass = checks["secure_qr"]["result"] == "pass" and checks["name_match"]["result"] == "pass" and checks["dob_match"]["result"] == "pass"
    status = "failed" if "fail" in results else "verified" if required_pass and "warn" not in results else "review"
    number_hash = hmac.new(hash_key, number.encode(), hashlib.sha256).hexdigest() if number and hash_key and verhoeff_valid(number) else None
    return Outcome(status, checks, f"XXXX XXXX {last4}" if last4 else None, number_hash)


def verify_image(image_bytes: bytes, *, expected_name: str, expected_dob: date | None, expected_gender: str | None, hash_key: bytes,
                 cert_path: str = "") -> Outcome:
    raw_qr, lines = read_image(image_bytes)
    cert = Path(cert_path).read_bytes() if cert_path else None
    qr = parse_secure_qr(raw_qr, cert) if raw_qr else None
    ocr = parse_ocr_lines(lines) if lines else None
    return evaluate(qr, ocr, expected_name=expected_name, expected_dob=expected_dob, expected_gender=expected_gender, hash_key=hash_key)
