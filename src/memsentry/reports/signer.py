"""Digital signature service for forensic reports using Ed25519."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import platformdirs

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class VerificationResult:
    """Result of verifying a report file against its detached signature manifest."""

    is_valid: bool
    hash_matches: bool
    signature_valid: bool
    key_fingerprint: str
    reason: str
    report_sha256: str = ""
    algorithm: str = ""
    signed_at_utc: str = ""


class ReportSigningService:
    """Signs report files with Ed25519 and verifies detached signature manifests."""

    def __init__(self, key_dir: Path | None = None) -> None:
        self.key_dir = key_dir or Path(platformdirs.user_config_dir("MemSentry")) / "keys"

    def get_or_create_key_pair(
        self,
    ) -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """Load the existing Ed25519 key pair, or generate and persist one if none exists."""
        self.key_dir.mkdir(parents=True, exist_ok=True)
        private_key_path = self.key_dir / "report_signing_key.pem"
        public_key_path = self.key_dir / "report_signing_key.pub"

        if private_key_path.is_file():
            pem_bytes = private_key_path.read_bytes()
            key = serialization.load_pem_private_key(pem_bytes, password=None)
            if not isinstance(key, ed25519.Ed25519PrivateKey):
                raise TypeError(f"Key in {private_key_path} is not an Ed25519 private key")
            return key, key.public_key()

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        private_key_path.write_bytes(private_pem)
        try:
            os.chmod(private_key_path, 0o600)
        except OSError:
            pass

        public_key_path.write_bytes(public_pem)
        logger.info("Generated new report signing key pair in %s", self.key_dir)
        return private_key, public_key

    def get_local_key_fingerprint(self) -> str | None:
        """Return the SHA-256 fingerprint of the local MemSentry public signing key, or None if no key exists."""
        public_key_path = self.key_dir / "report_signing_key.pub"
        if public_key_path.is_file():
            try:
                pem_bytes = public_key_path.read_bytes()
                key = serialization.load_pem_public_key(pem_bytes)
                if isinstance(key, ed25519.Ed25519PublicKey):
                    raw_pub = key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    )
                    return hashlib.sha256(raw_pub).hexdigest()
            except Exception as exc:
                logger.warning("Failed to load local public key: %s", exc)

        private_key_path = self.key_dir / "report_signing_key.pem"
        if private_key_path.is_file():
            try:
                pem_bytes = private_key_path.read_bytes()
                key = serialization.load_pem_private_key(pem_bytes, password=None)
                if isinstance(key, ed25519.Ed25519PrivateKey):
                    pub_key = key.public_key()
                    raw_pub = pub_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    )
                    return hashlib.sha256(raw_pub).hexdigest()
            except Exception as exc:
                logger.warning("Failed to load local private key: %s", exc)

        return None

    def sign_file(self, report_path: Path) -> Path:
        """Sign final on-disk report bytes and write detached <report>.sig.json manifest."""
        if not report_path.is_file():
            raise FileNotFoundError(f"Report file not found: {report_path}")

        report_bytes = report_path.read_bytes()
        digest_bytes = hashlib.sha256(report_bytes).digest()
        report_sha256 = digest_bytes.hex()

        private_key, public_key = self.get_or_create_key_pair()

        signature_bytes = private_key.sign(digest_bytes)
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

        raw_pub = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        public_key_b64 = base64.b64encode(raw_pub).decode("ascii")
        key_fingerprint = hashlib.sha256(raw_pub).hexdigest()

        manifest: dict[str, Any] = {
            "version": 1,
            "algorithm": "Ed25519",
            "digest_algorithm": "SHA-256",
            "report_filename": report_path.name,
            "report_sha256": report_sha256,
            "signature_base64": signature_b64,
            "public_key_base64": public_key_b64,
            "key_fingerprint_sha256": key_fingerprint,
            "signed_at_utc": datetime.now(UTC).isoformat(),
        }

        manifest_path = report_path.with_name(f"{report_path.name}.sig.json")
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return manifest_path

    @staticmethod
    def verify_file(report_path: Path, signature_manifest_path: Path) -> VerificationResult:
        """Verify report bytes against a detached signature manifest."""
        if not signature_manifest_path.is_file():
            return VerificationResult(
                is_valid=False,
                hash_matches=False,
                signature_valid=False,
                key_fingerprint="",
                reason=f"Signature manifest not found: {signature_manifest_path.name}",
            )

        try:
            manifest_text = signature_manifest_path.read_text(encoding="utf-8")
            manifest = json.loads(manifest_text)
            if not isinstance(manifest, dict):
                raise ValueError("Manifest content is not a JSON object")

            expected_sha256 = str(manifest.get("report_sha256", ""))
            signature_b64 = str(manifest.get("signature_base64", ""))
            public_key_b64 = str(manifest.get("public_key_base64", ""))
            manifest_fingerprint = str(manifest.get("key_fingerprint_sha256", ""))
            algorithm = str(manifest.get("algorithm", ""))
            digest_algo = str(manifest.get("digest_algorithm", ""))
            signed_at_utc = str(manifest.get("signed_at_utc", ""))

            if algorithm != "Ed25519" or digest_algo != "SHA-256":
                raise ValueError(f"Unsupported algorithm suite: {algorithm}/{digest_algo}")

            raw_public_key = base64.b64decode(public_key_b64)
            signature = base64.b64decode(signature_b64)
        except Exception as exc:
            return VerificationResult(
                is_valid=False,
                hash_matches=False,
                signature_valid=False,
                key_fingerprint="",
                reason=f"Malformed manifest: {exc}",
            )

        # Check key fingerprint consistency
        computed_fingerprint = hashlib.sha256(raw_public_key).hexdigest()
        if computed_fingerprint != manifest_fingerprint:
            return VerificationResult(
                is_valid=False,
                hash_matches=False,
                signature_valid=False,
                key_fingerprint=computed_fingerprint,
                reason="Manifest key fingerprint mismatch",
                report_sha256=expected_sha256,
                algorithm=algorithm,
                signed_at_utc=signed_at_utc,
            )

        if not report_path.is_file():
            return VerificationResult(
                is_valid=False,
                hash_matches=False,
                signature_valid=False,
                key_fingerprint=computed_fingerprint,
                reason=f"Report file not found: {report_path.name}",
                report_sha256=expected_sha256,
                algorithm=algorithm,
                signed_at_utc=signed_at_utc,
            )

        report_bytes = report_path.read_bytes()
        actual_digest = hashlib.sha256(report_bytes).digest()
        actual_sha256 = actual_digest.hex()

        if actual_sha256 != expected_sha256:
            return VerificationResult(
                is_valid=False,
                hash_matches=False,
                signature_valid=False,
                key_fingerprint=computed_fingerprint,
                reason="Report hash mismatch: content modified",
                report_sha256=actual_sha256,
                algorithm=algorithm,
                signed_at_utc=signed_at_utc,
            )

        try:
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(raw_public_key)
            pub_key.verify(signature, actual_digest)
        except InvalidSignature:
            return VerificationResult(
                is_valid=False,
                hash_matches=True,
                signature_valid=False,
                key_fingerprint=computed_fingerprint,
                reason="Invalid signature",
                report_sha256=actual_sha256,
                algorithm=algorithm,
                signed_at_utc=signed_at_utc,
            )
        except Exception as exc:
            return VerificationResult(
                is_valid=False,
                hash_matches=True,
                signature_valid=False,
                key_fingerprint=computed_fingerprint,
                reason=f"Signature verification error: {exc}",
                report_sha256=actual_sha256,
                algorithm=algorithm,
                signed_at_utc=signed_at_utc,
            )

        return VerificationResult(
            is_valid=True,
            hash_matches=True,
            signature_valid=True,
            key_fingerprint=computed_fingerprint,
            reason="Valid and unmodified",
            report_sha256=actual_sha256,
            algorithm=algorithm,
            signed_at_utc=signed_at_utc,
        )


def verify_file(report_path: Path, signature_manifest_path: Path) -> VerificationResult:
    """Convenience function to verify a report and its detached manifest."""
    return ReportSigningService.verify_file(report_path, signature_manifest_path)
