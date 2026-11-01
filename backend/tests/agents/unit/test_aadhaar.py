"""Aadhaar verification engine, using synthetic cards and a throwaway signing key. Never put real Aadhaar data in tests."""
import datetime as dt
import gzip

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from app.services import aadhaar as A

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuer")])
CERT = (x509.CertificateBuilder().subject_name(_name).issuer_name(_name).public_key(KEY.public_key()).serial_number(1)
        .not_valid_before(dt.datetime(2020, 1, 1)).not_valid_after(dt.datetime(2040, 1, 1)).sign(KEY, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM))
DOB = dt.date(1999, 5, 14)


def valid_number(prefix="23456789012"):
    return next(prefix + str(d) for d in range(10) if A.verhoeff_valid(prefix + str(d)))


def secure_qr(name="Aditya Rao", dob="14-05-1999", gender="M", ref="9012", key=KEY, version=True):
    fields = ([b"V2"] if version else []) + [b"3", f"{ref}20260101".encode(), name.encode(), dob.encode(), gender.encode(), b"Addr"]
    body = b"\xff".join(fields)
    packed = gzip.compress(body + key.sign(body, padding.PKCS1v15(), hashes.SHA256()))
    return str(int.from_bytes(packed, "big"))


def ocr_card(number, name="Aditya Rao", dob="14/05/1999", gender="MALE"):
    return A.parse_ocr_lines(["Government of India", name, f"DOB: {dob}", gender, f"{number[:4]} {number[4:8]} {number[8:]}"])


def run(qr, ocr, **kw):
    return A.evaluate(qr, ocr, **{"expected_name": "Aditya Rao", "expected_dob": DOB, "expected_gender": "M", "hash_key": b"k" * 32, **kw})


def test_verhoeff():
    n = valid_number()
    assert A.verhoeff_valid(n)
    assert not A.verhoeff_valid(n[:-1] + str((int(n[-1]) + 1) % 10))
    assert not A.verhoeff_valid("123456789012") and not A.verhoeff_valid("2345")


@pytest.mark.parametrize("version", [True, False])
def test_secure_qr_parsed_and_signature_checked(version):
    q = A.parse_secure_qr(secure_qr(version=version), CERT)
    assert q.parsed and q.signature == "valid"
    assert (q.data.name, q.data.dob, q.data.gender, q.data.last4) == ("Aditya Rao", "14-05-1999", "M", "9012")


def test_forged_signature_and_garbage_qr():
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert A.parse_secure_qr(secure_qr(key=other), CERT).signature == "invalid"
    assert A.parse_secure_qr(secure_qr(), None).signature == "unverified"
    assert not A.parse_secure_qr("https://example.com/not-aadhaar", CERT).parsed
    assert not A.parse_secure_qr("12345", CERT).parsed


def test_ocr_parsing():
    n = valid_number()
    d = ocr_card(n)
    assert (d.name, d.dob, d.gender, d.number, d.last4) == ("Aditya Rao", "14-05-1999", "M", n, n[-4:])
    assert A.parse_ocr_lines(["Aditya Rao", "Year of Birth : 1999", "Female"]).dob == "1999"


@pytest.mark.parametrize("a,b,ok", [("Aditya Rao", "ADITYA RAO", True), ("Rao Aditya", "Aditya Rao", True), ("Aditya R", "Aditya Rao", True),
                                    ("Aditya Rao", "Priya Sharma", False)])
def test_name_similarity(a, b, ok):
    assert (A.name_similarity(a, b) >= A.NAME_MATCH) is ok


def test_genuine_matching_card_is_verified_and_masked():
    n = valid_number()
    out = run(A.parse_secure_qr(secure_qr(ref=n[-4:]), CERT), ocr_card(n))
    assert out.status == "verified", out.checks
    assert out.masked == f"XXXX XXXX {n[-4:]}" and len(out.number_hash) == 64
    assert n not in repr(out)                                    # the full number never leaves the engine


def test_edited_print_is_caught_against_signed_qr():
    n = valid_number()
    out = run(A.parse_secure_qr(secure_qr(ref=n[-4:]), CERT), ocr_card(n, dob="14/05/1990"))
    assert out.status == "failed" and out.checks["print_vs_qr"]["result"] == "fail"


def test_forged_qr_fails():
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert run(A.parse_secure_qr(secure_qr(key=other), CERT), None).status == "failed"


def test_someone_elses_card_fails():
    q = A.parse_secure_qr(secure_qr(name="Priya Sharma"), CERT)
    assert run(q, None).status == "failed"


def test_wrong_dob_fails_and_bad_checksum_fails():
    assert run(A.parse_secure_qr(secure_qr(dob="01-01-1980"), CERT), None).status == "failed"
    n = valid_number()
    bad = n[:-1] + str((int(n[-1]) + 1) % 10)
    assert run(None, ocr_card(bad)).status == "failed"


def test_without_a_signature_the_best_result_is_review():
    n = valid_number()
    assert run(None, ocr_card(n)).status == "review"             # OCR alone can't prove authenticity
    assert run(A.parse_secure_qr(secure_qr(ref=n[-4:]), None), ocr_card(n)).status == "review"           # no certificate configured
    assert run(A.parse_secure_qr(secure_qr(ref=n[-4:]), CERT), ocr_card(n), expected_dob=None).status == "review"   # nothing to compare


def test_real_image_pipeline_with_a_synthetic_card():
    pytest.importorskip("rapidocr_onnxruntime")
    qrcode = pytest.importorskip("qrcode")
    from io import BytesIO

    from PIL import Image, ImageDraw, ImageFont
    n = valid_number()
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=4, border=4)
    qr.add_data(secure_qr(ref=n[-4:]))
    code = qr.make_image(fill_color="black", back_color="white").get_image().convert("RGB")
    card = Image.new("RGB", (code.width + 760, max(code.height, 520)), "white")
    card.paste(code, (740, 10))
    draw, font = ImageDraw.Draw(card), ImageFont.load_default(size=34)
    for y, line in zip((60, 130, 200, 300), ("Aditya Rao", "DOB: 14/05/1999", "MALE", f"{n[:4]} {n[4:8]} {n[8:]}")):
        draw.text((30, y), line, fill="black", font=font)
    buf = BytesIO()
    card.save(buf, "PNG")
    raw_qr, lines = A.read_image(buf.getvalue())
    assert raw_qr, "QR should decode"
    out = run(A.parse_secure_qr(raw_qr, CERT), A.parse_ocr_lines(lines))
    assert out.status == "verified", (out.checks, lines)
