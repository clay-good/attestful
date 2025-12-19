"""
Certificate management for mTLS authentication.

Handles generation, storage, and validation of certificates for
Docker scanner agents and host receiver.
"""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from attestful.core.logging import get_logger

logger = get_logger(__name__)


class CertificateManager:
    """
    Manages certificates for mTLS authentication.

    Handles CA, server, and client certificates.
    """

    def __init__(self, cert_dir: str = "certs") -> None:
        """
        Initialize certificate manager.

        Args:
            cert_dir: Directory to store certificates
        """
        self.cert_dir = Path(cert_dir)
        self.ca_dir = self.cert_dir / "ca"
        self.server_dir = self.cert_dir / "server"
        self.agents_dir = self.cert_dir / "agents"

        # Create directories
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.server_dir.mkdir(parents=True, exist_ok=True)
        self.agents_dir.mkdir(parents=True, exist_ok=True)

    def generate_ca_certificate(
        self,
        common_name: str = "Attestful CA",
        validity_days: int = 3650,  # 10 years
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """
        Generate a self-signed CA certificate.

        Args:
            common_name: Common name for the CA
            validity_days: Certificate validity in days

        Returns:
            Tuple of (certificate, private_key)
        """
        logger.info(f"Generating CA certificate: {common_name}")

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend(),
        )

        # Create certificate
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Attestful"),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(private_key, hashes.SHA256(), backend=default_backend())
        )

        logger.info(f"CA certificate generated: {cert.serial_number}")
        return cert, private_key

    def generate_server_certificate(
        self,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
        common_name: str = "localhost",
        san_dns: list[str] | None = None,
        san_ips: list[str] | None = None,
        validity_days: int = 365,
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """
        Generate a server certificate signed by the CA.

        Args:
            ca_cert: CA certificate
            ca_key: CA private key
            common_name: Common name for the server
            san_dns: Subject Alternative Names (DNS)
            san_ips: Subject Alternative Names (IP addresses)
            validity_days: Certificate validity in days

        Returns:
            Tuple of (certificate, private_key)
        """
        logger.info(f"Generating server certificate: {common_name}")

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

        # Create certificate
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Attestful"),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )

        # Build SAN extension
        san_list: list[x509.GeneralName] = []
        if san_dns:
            san_list.extend([x509.DNSName(dns) for dns in san_dns])
        if san_ips:
            san_list.extend([x509.IPAddress(ip) for ip in san_ips])  # type: ignore[arg-type]

        if not san_list:
            san_list = [x509.DNSName(common_name)]

        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
            .add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=True,
            )
        )

        cert = cert_builder.sign(ca_key, hashes.SHA256(), backend=default_backend())

        logger.info(f"Server certificate generated: {cert.serial_number}")
        return cert, private_key

    def generate_client_certificate(
        self,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
        common_name: str,
        validity_days: int = 365,
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """
        Generate a client certificate signed by the CA.

        Args:
            ca_cert: CA certificate
            ca_key: CA private key
            common_name: Common name for the client (agent ID)
            validity_days: Certificate validity in days

        Returns:
            Tuple of (certificate, private_key)
        """
        logger.info(f"Generating client certificate: {common_name}")

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

        # Create certificate
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Attestful"),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256(), backend=default_backend())
        )

        logger.info(f"Client certificate generated: {cert.serial_number}")
        return cert, private_key

    def save_certificate(
        self,
        cert: x509.Certificate,
        private_key: rsa.RSAPrivateKey,
        cert_path: Path,
        key_path: Path,
    ) -> None:
        """
        Save certificate and private key to files.

        Args:
            cert: Certificate
            private_key: Private key
            cert_path: Path to save certificate
            key_path: Path to save private key
        """
        # Save certificate
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # Save private key with secure permissions
        with open(key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Set secure permissions (0600)
        os.chmod(key_path, 0o600)

        logger.info(f"Certificate saved: {cert_path}")
        logger.info(f"Private key saved: {key_path} (permissions: 0600)")

    def load_certificate(self, cert_path: Path) -> x509.Certificate:
        """
        Load certificate from file.

        Args:
            cert_path: Path to certificate file

        Returns:
            Certificate
        """
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), backend=default_backend())
        return cert

    def load_private_key(self, key_path: Path) -> rsa.RSAPrivateKey:
        """
        Load private key from file.

        Args:
            key_path: Path to private key file

        Returns:
            Private key
        """
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend(),
            )
        return key  # type: ignore[return-value]

    def verify_certificate(
        self,
        cert: x509.Certificate,
        ca_cert: x509.Certificate,
    ) -> bool:
        """
        Verify that a certificate was signed by the CA.

        Args:
            cert: Certificate to verify
            ca_cert: CA certificate

        Returns:
            True if certificate is valid
        """
        try:
            ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_algorithm_parameters,  # type: ignore[arg-type]
            )
            return True
        except Exception as e:
            logger.warning(f"Certificate verification failed: {e}")
            return False

    def is_certificate_expired(self, cert: x509.Certificate) -> bool:
        """
        Check if a certificate has expired.

        Args:
            cert: Certificate to check

        Returns:
            True if certificate is expired
        """
        return datetime.now(timezone.utc) > cert.not_valid_after_utc
