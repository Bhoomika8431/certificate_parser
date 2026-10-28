
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def generate_certificate():
    print("Generating RSA private key...")

    # 1. Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 2. Define the certificate subject
    subject = x509.Name([
        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME,
            "X509 Parser Test",
        ),
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            "localhost",
        ),
    ])

    now = datetime.now(timezone.utc)

    # 3. Build a self-signed server certificate
    certificate_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))

        # This is an end-entity certificate, not a CA certificate
        .add_extension(
            x509.BasicConstraints(
                ca=False,
                path_length=None,
            ),
            critical=True,
        )

        # Identify the certificate's public key
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                private_key.public_key()
            ),
            critical=False,
        )

        # Identify the authority that signed this certificate
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                private_key.public_key()
            ),
            critical=False,
        )

        # Hostname used for testing
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
            ]),
            critical=False,
        )

        # Permit TLS server authentication
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=False,
        )

        # Server key usage; this certificate cannot sign other certificates
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
    )

    # 4. Sign the certificate with its own private key
    certificate = certificate_builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
    )

    # 5. Save the certificate
    certificate_path = Path("certificate.pem")
    certificate_path.write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )

    # 6. Save the private key
    private_key_path = Path("private_key.pem")
    private_key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    # 7. Display confirmation
    print("\nCertificate generated successfully!")
    print(f"Certificate: {certificate_path.resolve()}")
    print(f"Private key: {private_key_path.resolve()}")
    print(f"Serial number: {certificate.serial_number}")

    print("\nCertificate extensions:")
    for extension in certificate.extensions:
        print(f"- {extension.oid._name}")

    print("\nHostname: localhost")
    print("Validity: 30 days")
    print("Certificate type: Self-signed server certificate")
    print("Note: Intended for local testing only.")


if __name__ == "__main__":
    try:
        generate_certificate()
    except Exception as error:
        print(f"Certificate generation failed: {error}")
        raise
