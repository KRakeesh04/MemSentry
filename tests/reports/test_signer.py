from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from memsentry.reports.signer import ReportSigningService, verify_file


def test_key_generation_and_reuse(tmp_path: Path):
    key_dir = tmp_path / "test_keys"
    service = ReportSigningService(key_dir=key_dir)

    # 1. No key initially
    assert not (key_dir / "report_signing_key.pem").exists()
    assert not (key_dir / "report_signing_key.pub").exists()
    assert service.get_local_key_fingerprint() is None

    # First access generates pair
    priv1, pub1 = service.get_or_create_key_pair()
    assert (key_dir / "report_signing_key.pem").exists()
    assert (key_dir / "report_signing_key.pub").exists()

    fp1 = service.get_local_key_fingerprint()
    assert fp1 is not None

    # Subsequent access reuses the same key
    service2 = ReportSigningService(key_dir=key_dir)
    priv2, pub2 = service2.get_or_create_key_pair()
    fp2 = service2.get_local_key_fingerprint()

    assert fp1 == fp2
    raw1 = pub1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    raw2 = pub2.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert raw1 == raw2


def test_sign_html_and_verify(tmp_path: Path):
    key_dir = tmp_path / "keys"
    report_file = tmp_path / "MemSentry-Report-CASE001.html"
    report_file.write_text("<html><body>Report Content</body></html>", encoding="utf-8")

    signer = ReportSigningService(key_dir=key_dir)
    manifest_path = signer.sign_file(report_file)

    assert manifest_path.name == "MemSentry-Report-CASE001.html.sig.json"
    assert manifest_path.is_file()

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["version"] == 1
    assert manifest["algorithm"] == "Ed25519"
    assert manifest["digest_algorithm"] == "SHA-256"
    assert manifest["report_filename"] == "MemSentry-Report-CASE001.html"
    assert manifest["report_sha256"] == hashlib.sha256(report_file.read_bytes()).hexdigest()
    assert "signature_base64" in manifest
    assert "public_key_base64" in manifest
    assert manifest["key_fingerprint_sha256"] == signer.get_local_key_fingerprint()
    assert "signed_at_utc" in manifest

    # Valid verification
    result = verify_file(report_file, manifest_path)
    assert result.is_valid is True
    assert result.hash_matches is True
    assert result.signature_valid is True
    assert result.key_fingerprint == manifest["key_fingerprint_sha256"]
    assert result.reason == "Valid and unmodified"


def test_sign_json_and_verify(tmp_path: Path):
    key_dir = tmp_path / "keys"
    report_file = tmp_path / "MemSentry-Report-CASE001.json"
    report_file.write_text(json.dumps({"case": "CASE001", "findings": []}), encoding="utf-8")

    signer = ReportSigningService(key_dir=key_dir)
    manifest_path = signer.sign_file(report_file)

    assert manifest_path.name == "MemSentry-Report-CASE001.json.sig.json"
    result = verify_file(report_file, manifest_path)
    assert result.is_valid is True
    assert result.hash_matches is True
    assert result.signature_valid is True


def test_tampering_one_byte(tmp_path: Path):
    key_dir = tmp_path / "keys"
    report_file = tmp_path / "report.html"
    report_file.write_text("Original content", encoding="utf-8")

    signer = ReportSigningService(key_dir=key_dir)
    manifest_path = signer.sign_file(report_file)

    # Tamper with 1 byte of the report
    report_file.write_text("Xriginal content", encoding="utf-8")

    result = verify_file(report_file, manifest_path)
    assert result.is_valid is False
    assert result.hash_matches is False
    assert "Report hash mismatch: content modified" in result.reason


def test_tampering_signature(tmp_path: Path):
    key_dir = tmp_path / "keys"
    report_file = tmp_path / "report.html"
    report_file.write_text("Untouched content", encoding="utf-8")

    signer = ReportSigningService(key_dir=key_dir)
    manifest_path = signer.sign_file(report_file)

    # Corrupt the signature bytes
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw_sig = bytearray(base64.b64decode(manifest["signature_base64"]))
    raw_sig[0] ^= 0xFF
    manifest["signature_base64"] = base64.b64encode(raw_sig).decode("ascii")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = verify_file(report_file, manifest_path)
    assert result.is_valid is False
    assert result.hash_matches is True
    assert result.signature_valid is False
    assert "Invalid signature" in result.reason


def test_malformed_manifests(tmp_path: Path):
    key_dir = tmp_path / "keys"
    report_file = tmp_path / "report.html"
    report_file.write_text("Untouched content", encoding="utf-8")

    signer = ReportSigningService(key_dir=key_dir)
    manifest_path = signer.sign_file(report_file)

    # 1. Non-JSON text
    manifest_path.write_text("NOT_JSON{{{", encoding="utf-8")
    res1 = verify_file(report_file, manifest_path)
    assert res1.is_valid is False
    assert "Malformed manifest" in res1.reason

    # 2. Missing field
    manifest_path.write_text(json.dumps({"algorithm": "Ed25519"}), encoding="utf-8")
    res2 = verify_file(report_file, manifest_path)
    assert res2.is_valid is False
    assert "Malformed manifest" in res2.reason

    # 3. Invalid base64
    manifest = {
        "report_sha256": "abc",
        "signature_base64": "!!!not_base64",
        "public_key_base64": "!!!not_base64",
        "key_fingerprint_sha256": "123",
        "algorithm": "Ed25519",
        "digest_algorithm": "SHA-256",
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    res3 = verify_file(report_file, manifest_path)
    assert res3.is_valid is False
    assert "Malformed manifest" in res3.reason


def test_different_signing_key_and_no_local_key(tmp_path: Path):
    key_dir_a = tmp_path / "keys_a"
    key_dir_b = tmp_path / "keys_b"
    empty_key_dir = tmp_path / "keys_empty"

    report_file = tmp_path / "report.html"
    report_file.write_text("Report signed with key A", encoding="utf-8")

    signer_a = ReportSigningService(key_dir=key_dir_a)
    manifest_path = signer_a.sign_file(report_file)

    # Cryptographic verification should succeed
    result = verify_file(report_file, manifest_path)
    assert result.is_valid is True
    assert result.hash_matches is True
    assert result.signature_valid is True

    # Check against local key B: fingerprint should not match
    signer_b = ReportSigningService(key_dir=key_dir_b)
    signer_b.get_or_create_key_pair()
    fp_b = signer_b.get_local_key_fingerprint()
    assert fp_b is not None
    assert fp_b != result.key_fingerprint

    # Check with empty local key dir: verification must NOT generate keys
    signer_empty = ReportSigningService(key_dir=empty_key_dir)
    assert signer_empty.get_local_key_fingerprint() is None
    assert not (empty_key_dir / "report_signing_key.pem").exists()
    assert not (empty_key_dir / "report_signing_key.pub").exists()
