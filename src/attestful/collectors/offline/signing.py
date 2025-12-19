"""
Evidence Bundle Signing and Verification.

Provides cryptographic signing and verification for evidence bundles
to ensure authenticity and integrity in air-gapped transfers.

Supports:
- RSA key pairs for signing (default)
- GPG/PGP keys for existing PKI infrastructure
- Ed25519 keys for modern, fast signing

Key Management:
- Generate organization keypairs during setup
- Store private keys securely (encrypted)
- Distribute public keys for verification
- Support key rotation and revocation
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from attestful.collectors.offline.bundle import BundleSignature
from attestful.core.exceptions import SecurityError, ValidationError
from attestful.core.logging import get_logger

logger = get_logger(__name__)


# =============================================================================
# Key Types
# =============================================================================


@dataclass
class SigningKey:
    """
    Private key for signing bundles.

    Contains the private key material and metadata.
    """

    key_id: str = ""
    algorithm: str = "RSA-SHA256"  # RSA-SHA256, ED25519, GPG
    key_data: bytes = b""
    key_path: Path | None = None
    fingerprint: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    passphrase: str | None = None  # For encrypted keys

    @property
    def is_expired(self) -> bool:
        """Check if key is expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at


@dataclass
class VerificationKey:
    """
    Public key for verifying bundle signatures.

    Contains the public key material and metadata.
    """

    key_id: str = ""
    algorithm: str = "RSA-SHA256"
    key_data: bytes = b""
    key_path: Path | None = None
    fingerprint: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    organization_id: str = ""
    organization_name: str = ""

    @property
    def is_expired(self) -> bool:
        """Check if key is expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at


# =============================================================================
# Key Manager
# =============================================================================


class KeyManager:
    """
    Manages signing and verification keys.

    Handles key generation, storage, loading, and distribution.

    Example:
        manager = KeyManager(keys_dir=Path("/etc/attestful/keys"))

        # Generate new keypair
        signing_key, verification_key = manager.generate_keypair(
            organization_id="acme",
            algorithm="RSA-SHA256",
        )

        # Save keys
        manager.save_signing_key(signing_key, "acme_private.pem")
        manager.save_verification_key(verification_key, "acme_public.pem")

        # Load key
        signing_key = manager.load_signing_key("acme_private.pem")
    """

    def __init__(self, keys_dir: Path | str | None = None) -> None:
        """
        Initialize key manager.

        Args:
            keys_dir: Directory for key storage
        """
        self.keys_dir = Path(keys_dir) if keys_dir else Path.home() / ".attestful" / "keys"
        self.keys_dir.mkdir(parents=True, exist_ok=True)

    def generate_keypair(
        self,
        *,
        organization_id: str = "",
        algorithm: str = "RSA-SHA256",
        key_size: int = 4096,
        expires_days: int | None = None,
        passphrase: str | None = None,
    ) -> tuple[SigningKey, VerificationKey]:
        """
        Generate a new signing/verification keypair.

        Args:
            organization_id: Organization identifier
            algorithm: Signing algorithm (RSA-SHA256, ED25519)
            key_size: RSA key size in bits (default: 4096)
            expires_days: Days until key expiration (None = no expiration)
            passphrase: Passphrase to encrypt private key

        Returns:
            Tuple of (SigningKey, VerificationKey)
        """
        key_id = str(uuid4())
        created_at = datetime.now(timezone.utc)
        expires_at = None
        if expires_days:
            from datetime import timedelta

            expires_at = created_at + timedelta(days=expires_days)

        if algorithm == "RSA-SHA256":
            private_key_data, public_key_data, fingerprint = self._generate_rsa_keypair(
                key_size, passphrase
            )
        elif algorithm == "ED25519":
            private_key_data, public_key_data, fingerprint = self._generate_ed25519_keypair()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        signing_key = SigningKey(
            key_id=key_id,
            algorithm=algorithm,
            key_data=private_key_data,
            fingerprint=fingerprint,
            created_at=created_at,
            expires_at=expires_at,
            passphrase=passphrase,
        )

        verification_key = VerificationKey(
            key_id=key_id,
            algorithm=algorithm,
            key_data=public_key_data,
            fingerprint=fingerprint,
            created_at=created_at,
            expires_at=expires_at,
            organization_id=organization_id,
        )

        logger.info(f"Generated {algorithm} keypair: {key_id}")
        return signing_key, verification_key

    def _generate_rsa_keypair(
        self,
        key_size: int,
        passphrase: str | None,
    ) -> tuple[bytes, bytes, str]:
        """Generate RSA keypair."""
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
        except ImportError:
            raise ImportError(
                "cryptography package required for RSA signing. "
                "Install with: pip install cryptography"
            )

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        # Serialize private key
        encryption = (
            serialization.BestAvailableEncryption(passphrase.encode())
            if passphrase
            else serialization.NoEncryption()
        )
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

        # Get public key
        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Calculate fingerprint
        fingerprint = hashlib.sha256(public_key_pem).hexdigest()[:32]

        return private_key_pem, public_key_pem, fingerprint

    def _generate_ed25519_keypair(self) -> tuple[bytes, bytes, str]:
        """Generate Ed25519 keypair."""
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519
        except ImportError:
            raise ImportError(
                "cryptography package required for Ed25519 signing. "
                "Install with: pip install cryptography"
            )

        # Generate private key
        private_key = ed25519.Ed25519PrivateKey.generate()

        # Serialize private key
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Get public key
        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Calculate fingerprint
        fingerprint = hashlib.sha256(public_key_pem).hexdigest()[:32]

        return private_key_pem, public_key_pem, fingerprint

    def save_signing_key(
        self,
        key: SigningKey,
        filename: str,
        encrypt: bool = True,
    ) -> Path:
        """
        Save signing key to file.

        Args:
            key: SigningKey to save
            filename: Output filename
            encrypt: Whether to encrypt the key file

        Returns:
            Path to saved key file
        """
        key_path = self.keys_dir / filename
        key_path.parent.mkdir(parents=True, exist_ok=True)

        # Write key data
        with open(key_path, "wb") as f:
            f.write(key.key_data)

        # Set restrictive permissions
        os.chmod(key_path, 0o600)

        # Save metadata
        metadata_path = key_path.with_suffix(key_path.suffix + ".meta")
        metadata = {
            "key_id": key.key_id,
            "algorithm": key.algorithm,
            "fingerprint": key.fingerprint,
            "created_at": key.created_at.isoformat(),
            "expires_at": key.expires_at.isoformat() if key.expires_at else None,
        }
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"Saved signing key: {key_path}")
        return key_path

    def save_verification_key(
        self,
        key: VerificationKey,
        filename: str,
    ) -> Path:
        """
        Save verification key to file.

        Args:
            key: VerificationKey to save
            filename: Output filename

        Returns:
            Path to saved key file
        """
        key_path = self.keys_dir / filename
        key_path.parent.mkdir(parents=True, exist_ok=True)

        # Write key data
        with open(key_path, "wb") as f:
            f.write(key.key_data)

        # Save metadata
        metadata_path = key_path.with_suffix(key_path.suffix + ".meta")
        metadata = {
            "key_id": key.key_id,
            "algorithm": key.algorithm,
            "fingerprint": key.fingerprint,
            "created_at": key.created_at.isoformat(),
            "expires_at": key.expires_at.isoformat() if key.expires_at else None,
            "organization_id": key.organization_id,
            "organization_name": key.organization_name,
        }
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"Saved verification key: {key_path}")
        return key_path

    def load_signing_key(
        self,
        key_path: Path | str,
        passphrase: str | None = None,
    ) -> SigningKey:
        """
        Load signing key from file.

        Args:
            key_path: Path to key file
            passphrase: Passphrase if key is encrypted

        Returns:
            SigningKey instance
        """
        key_path = Path(key_path)
        if not key_path.is_absolute():
            key_path = self.keys_dir / key_path

        if not key_path.exists():
            raise FileNotFoundError(f"Key file not found: {key_path}")

        with open(key_path, "rb") as f:
            key_data = f.read()

        # Load metadata if exists
        metadata_path = key_path.with_suffix(key_path.suffix + ".meta")
        metadata = {}
        if metadata_path.exists():
            with open(metadata_path, "r") as f:
                metadata = json.load(f)

        # Parse expiration
        expires_at = None
        if metadata.get("expires_at"):
            expires_at = datetime.fromisoformat(metadata["expires_at"])

        return SigningKey(
            key_id=metadata.get("key_id", ""),
            algorithm=metadata.get("algorithm", "RSA-SHA256"),
            key_data=key_data,
            key_path=key_path,
            fingerprint=metadata.get("fingerprint", ""),
            expires_at=expires_at,
            passphrase=passphrase,
        )

    def load_verification_key(self, key_path: Path | str) -> VerificationKey:
        """
        Load verification key from file.

        Args:
            key_path: Path to key file

        Returns:
            VerificationKey instance
        """
        key_path = Path(key_path)
        if not key_path.is_absolute():
            key_path = self.keys_dir / key_path

        if not key_path.exists():
            raise FileNotFoundError(f"Key file not found: {key_path}")

        with open(key_path, "rb") as f:
            key_data = f.read()

        # Load metadata if exists
        metadata_path = key_path.with_suffix(key_path.suffix + ".meta")
        metadata = {}
        if metadata_path.exists():
            with open(metadata_path, "r") as f:
                metadata = json.load(f)

        # Parse expiration
        expires_at = None
        if metadata.get("expires_at"):
            expires_at = datetime.fromisoformat(metadata["expires_at"])

        return VerificationKey(
            key_id=metadata.get("key_id", ""),
            algorithm=metadata.get("algorithm", "RSA-SHA256"),
            key_data=key_data,
            key_path=key_path,
            fingerprint=metadata.get("fingerprint", ""),
            expires_at=expires_at,
            organization_id=metadata.get("organization_id", ""),
            organization_name=metadata.get("organization_name", ""),
        )


# =============================================================================
# Signing Functions
# =============================================================================


def sign_bundle(
    content_path: Path | str,
    *,
    key_path: Path | str | None = None,
    key_id: str = "",
    passphrase: str | None = None,
    algorithm: str = "RSA-SHA256",
) -> BundleSignature:
    """
    Sign bundle content (typically the checksums file).

    Args:
        content_path: Path to content to sign
        key_path: Path to signing key
        key_id: Key identifier
        passphrase: Passphrase for encrypted key
        algorithm: Signing algorithm

    Returns:
        BundleSignature with signature data
    """
    content_path = Path(content_path)

    if not content_path.exists():
        raise FileNotFoundError(f"Content not found: {content_path}")

    # Read content to sign
    with open(content_path, "rb") as f:
        content = f.read()

    # Calculate content hash
    content_hash = hashlib.sha256(content).hexdigest()

    # Load signing key
    if key_path:
        manager = KeyManager()
        signing_key = manager.load_signing_key(key_path, passphrase)
    else:
        # No key provided - return placeholder signature
        logger.warning("No signing key provided, bundle will be unsigned")
        return BundleSignature(
            algorithm="none",
            signed_content_hash=content_hash,
        )

    # Sign content
    if algorithm in ("RSA-SHA256", "RSA"):
        signature = _sign_rsa(content, signing_key)
    elif algorithm == "ED25519":
        signature = _sign_ed25519(content, signing_key)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    # Create signature object
    signature_b64 = base64.b64encode(signature).decode("ascii")

    bundle_sig = BundleSignature(
        signature=signature,
        signature_base64=signature_b64,
        algorithm=algorithm,
        key_id=signing_key.key_id,
        key_fingerprint=signing_key.fingerprint,
        signed_content_hash=content_hash,
    )

    # Save signature file
    sig_path = content_path.parent / "signature.sig"
    with open(sig_path, "w") as f:
        json.dump(bundle_sig.to_dict(), f, indent=2)

    logger.info(f"Created signature for {content_path.name}")
    return bundle_sig


def _sign_rsa(content: bytes, key: SigningKey) -> bytes:
    """Sign content with RSA key."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:
        raise ImportError("cryptography package required")

    # Load private key
    password = key.passphrase.encode() if key.passphrase else None
    private_key = serialization.load_pem_private_key(key.key_data, password=password)

    # Sign
    signature = private_key.sign(
        content,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return signature


def _sign_ed25519(content: bytes, key: SigningKey) -> bytes:
    """Sign content with Ed25519 key."""
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        raise ImportError("cryptography package required")

    # Load private key
    private_key = serialization.load_pem_private_key(key.key_data, password=None)

    # Sign
    signature = private_key.sign(content)

    return signature


# =============================================================================
# Verification Functions
# =============================================================================


def verify_bundle_signature(
    content_path: Path | str,
    signature_path: Path | str | None = None,
    *,
    key_path: Path | str | None = None,
) -> bool:
    """
    Verify bundle signature.

    Args:
        content_path: Path to signed content
        signature_path: Path to signature file (default: same dir as content)
        key_path: Path to verification key

    Returns:
        True if signature is valid

    Raises:
        SecurityError: If verification fails
    """
    content_path = Path(content_path)

    # Find signature file
    if signature_path:
        sig_path = Path(signature_path)
    else:
        sig_path = content_path.parent / "signature.sig"

    if not sig_path.exists():
        logger.warning("No signature file found")
        return False

    # Load signature
    with open(sig_path, "r") as f:
        sig_data = json.load(f)

    signature = BundleSignature.from_dict(sig_data)

    if not signature.signature:
        logger.warning("Empty signature")
        return False

    # Read content
    with open(content_path, "rb") as f:
        content = f.read()

    # Verify content hash
    content_hash = hashlib.sha256(content).hexdigest()
    if signature.signed_content_hash and signature.signed_content_hash != content_hash:
        logger.error("Content hash mismatch - content may have been modified")
        return False

    # Load verification key
    if not key_path:
        logger.warning("No verification key provided, cannot verify signature")
        return False

    manager = KeyManager()
    verification_key = manager.load_verification_key(key_path)

    # Check key expiration
    if verification_key.is_expired:
        logger.warning("Verification key is expired")
        return False

    # Verify signature
    try:
        if signature.algorithm in ("RSA-SHA256", "RSA"):
            _verify_rsa(content, signature.signature, verification_key)
        elif signature.algorithm == "ED25519":
            _verify_ed25519(content, signature.signature, verification_key)
        else:
            logger.error(f"Unsupported algorithm: {signature.algorithm}")
            return False

        logger.info("Signature verified successfully")
        return True

    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False


def _verify_rsa(content: bytes, signature: bytes, key: VerificationKey) -> None:
    """Verify RSA signature."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:
        raise ImportError("cryptography package required")

    # Load public key
    public_key = serialization.load_pem_public_key(key.key_data)

    # Verify
    public_key.verify(
        signature,
        content,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def _verify_ed25519(content: bytes, signature: bytes, key: VerificationKey) -> None:
    """Verify Ed25519 signature."""
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        raise ImportError("cryptography package required")

    # Load public key
    public_key = serialization.load_pem_public_key(key.key_data)

    # Verify
    public_key.verify(signature, content)


# =============================================================================
# Convenience Functions
# =============================================================================


def generate_keypair(
    output_dir: Path | str = ".",
    *,
    organization_id: str = "",
    organization_name: str = "",
    algorithm: str = "RSA-SHA256",
    passphrase: str | None = None,
) -> tuple[Path, Path]:
    """
    Generate a new keypair and save to files.

    Convenience function for quick key generation.

    Args:
        output_dir: Directory for key files
        organization_id: Organization identifier
        organization_name: Organization display name
        algorithm: Signing algorithm
        passphrase: Passphrase for private key

    Returns:
        Tuple of (private_key_path, public_key_path)

    Example:
        private_path, public_path = generate_keypair(
            output_dir="/etc/attestful/keys",
            organization_name="Acme Corp",
        )
    """
    output_dir = Path(output_dir)
    manager = KeyManager(keys_dir=output_dir)

    signing_key, verification_key = manager.generate_keypair(
        organization_id=organization_id,
        algorithm=algorithm,
        passphrase=passphrase,
    )

    verification_key.organization_name = organization_name

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    private_path = manager.save_signing_key(
        signing_key, f"attestful_private_{timestamp}.pem"
    )
    public_path = manager.save_verification_key(
        verification_key, f"attestful_public_{timestamp}.pem"
    )

    return private_path, public_path


def setup_organization_keys(
    organization_id: str,
    organization_name: str,
    keys_dir: Path | str | None = None,
) -> dict[str, Any]:
    """
    Set up signing keys for an organization.

    Creates a new keypair and returns paths and metadata.

    Args:
        organization_id: Organization identifier
        organization_name: Organization display name
        keys_dir: Directory for keys (default: ~/.attestful/keys)

    Returns:
        Dictionary with key paths and metadata
    """
    keys_dir = Path(keys_dir) if keys_dir else Path.home() / ".attestful" / "keys"
    manager = KeyManager(keys_dir=keys_dir)

    signing_key, verification_key = manager.generate_keypair(
        organization_id=organization_id,
        algorithm="RSA-SHA256",
        key_size=4096,
    )
    verification_key.organization_name = organization_name

    private_path = manager.save_signing_key(
        signing_key, f"{organization_id}_private.pem"
    )
    public_path = manager.save_verification_key(
        verification_key, f"{organization_id}_public.pem"
    )

    return {
        "organization_id": organization_id,
        "organization_name": organization_name,
        "key_id": signing_key.key_id,
        "fingerprint": signing_key.fingerprint,
        "algorithm": signing_key.algorithm,
        "private_key_path": str(private_path),
        "public_key_path": str(public_path),
        "created_at": signing_key.created_at.isoformat(),
    }
