
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def save_private_key(key, filename):
    Path(filename).write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def save_certificate(cert, filename):
    Path(filename).write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )


def generate_chain():
    now = datetime.now(timezone.utc)

    # 1. Generate the Root CA key and certificate
    print("Generating Root CA...")
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    ca_name = x509.Name([
        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME, "X509 Test CA"
        ),
        x509.NameAttribute(
            NameOID.COMMON_NAME, "X509 Test Root CA"
        ),
    ])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                ca_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    save_certificate(ca_cert, "root_ca.pem")
    save_private_key(ca_key, "root_ca_key.pem")

    # 2. Generate the localhost server key
    print("Generating localhost server certificate...")
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    server_name = x509.Name([
        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME, "X509 Parser Test"
        ),
        x509.NameAttribute(
            NameOID.COMMON_NAME, "localhost"
        ),
    ])

    # 3. Create a server certificate signed by the Root CA
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                server_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
            ]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    save_certificate(server_cert, "server_certificate.pem")
    save_private_key(server_key, "server_key.pem")

    print("\nCertificate chain generated successfully!")
    print("Root CA: root_ca.pem")
    print("Server certificate: server_certificate.pem")
    print("Private keys: root_ca_key.pem, server_key.pem")
    print("Server hostname: localhost")
    print("The server certificate is signed by the Root CA.")


if __name__ == "__main__":
    generate_chain()
