
import argparse
import ipaddress
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import certifi
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    ed448,
    padding,
    rsa,
)
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError


def get_name(name):
    """Convert an X.509 name into readable text."""
    return ", ".join(
        f"{attribute.oid._name or attribute.oid.dotted_string}="
        f"{attribute.value}"
        for attribute in name
    )


def load_certificate(file_path):
    """Load one PEM-encoded X.509 certificate."""
    path = Path(file_path)
    return x509.load_pem_x509_certificate(path.read_bytes())


def load_certificates(file_path):
    """Load one or more PEM certificates from a file."""
    path = Path(file_path)
    return x509.load_pem_x509_certificates(path.read_bytes())


def get_public_key_details(key):
    """Extract public-key algorithm information."""
    details = {
        "algorithm": type(key).__name__,
        "key_size": getattr(key, "key_size", None),
    }

    if isinstance(key, rsa.RSAPublicKey):
        details.update({
            "algorithm": "RSA",
            "public_exponent": key.public_numbers().e,
        })
    elif isinstance(key, ec.EllipticCurvePublicKey):
        details.update({
            "algorithm": "Elliptic Curve",
            "curve": key.curve.name,
        })
    elif isinstance(key, dsa.DSAPublicKey):
        details["algorithm"] = "DSA"
    elif isinstance(key, ed25519.Ed25519PublicKey):
        details["algorithm"] = "Ed25519"
    elif isinstance(key, ed448.Ed448PublicKey):
        details["algorithm"] = "Ed448"

    return details


def verify_signature(cert, issuer_cert=None):
    """Verify a certificate's signature using its issuer's public key."""
    if issuer_cert is None:
        if cert.subject != cert.issuer:
            return {
                "status": "NOT CHECKED",
                "details": (
                    "Provide the issuer certificate using --issuer."
                ),
            }
        issuer_cert = cert

    if cert.issuer != issuer_cert.subject:
        return {
            "status": "FAILED",
            "details": (
                "Issuer subject does not match certificate issuer."
            ),
        }

    key = issuer_cert.public_key()

    try:
        signature = cert.signature
        data = cert.tbs_certificate_bytes

        if isinstance(key, rsa.RSAPublicKey):
            parameters = cert.signature_algorithm_parameters
            algorithm = cert.signature_hash_algorithm

            if parameters is None or algorithm is None:
                return {
                    "status": "NOT CHECKED",
                    "details": "RSA signature parameters are unavailable.",
                }

            key.verify(signature, data, parameters, algorithm)

        elif isinstance(key, ec.EllipticCurvePublicKey):
            parameters = cert.signature_algorithm_parameters

            if parameters is None:
                algorithm = cert.signature_hash_algorithm
                if algorithm is None:
                    return {
                        "status": "NOT CHECKED",
                        "details": "ECDSA signature parameters are unavailable.",
                    }
                parameters = ec.ECDSA(algorithm)

            key.verify(signature, data, parameters)

        elif isinstance(key, dsa.DSAPublicKey):
            algorithm = cert.signature_hash_algorithm
            if algorithm is None:
                return {
                    "status": "NOT CHECKED",
                    "details": "DSA signature hash is unavailable.",
                }
            key.verify(signature, data, algorithm)

        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(signature, data)

        else:
            return {
                "status": "NOT CHECKED",
                "details": "Unsupported issuer public-key algorithm.",
            }

        return {
            "status": "PASSED",
            "details": "Certificate signature is valid.",
        }

    except InvalidSignature:
        return {
            "status": "FAILED",
            "details": "Certificate signature is invalid.",
        }
    except (ValueError, TypeError, NotImplementedError) as error:
        return {
            "status": "FAILED",
            "details": f"Signature verification error: {error}",
        }


def dns_name_matches(hostname, certificate_name):
    """Match a DNS hostname, including a single-label wildcard."""
    hostname = hostname.rstrip(".").lower()
    certificate_name = certificate_name.rstrip(".").lower()

    if "*" not in certificate_name:
        return hostname == certificate_name

    # Only allow a wildcard as the complete leftmost label.
    if not certificate_name.startswith("*."):
        return False

    if certificate_name.count("*") != 1:
        return False

    hostname_labels = hostname.split(".")
    certificate_labels = certificate_name.split(".")

    return (
        len(hostname_labels) == len(certificate_labels)
        and hostname_labels[1:] == certificate_labels[1:]
        and bool(hostname_labels[0])
    )


def verify_hostname(cert, hostname):
    """Check a DNS hostname or IP address against the certificate SAN."""
    if not hostname:
        return {
            "status": "NOT CHECKED",
            "details": "No hostname provided.",
        }

    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        return {
            "status": "FAILED",
            "details": "Certificate has no Subject Alternative Name (SAN).",
        }

    try:
        ip_address = ipaddress.ip_address(hostname)
    except ValueError:
        ip_address = None

    if ip_address is not None:
        certificate_addresses = san.get_values_for_type(x509.IPAddress)

        if ip_address in certificate_addresses:
            return {
                "status": "PASSED",
                "details": f"IP address {hostname} matches the certificate SAN.",
            }

        return {
            "status": "FAILED",
            "details": f"No matching IP SAN for {hostname}.",
        }

    dns_names = san.get_values_for_type(x509.DNSName)

    for certificate_name in dns_names:
        if dns_name_matches(hostname, certificate_name):
            return {
                "status": "PASSED",
                "details": f"Hostname {hostname} matches the certificate SAN.",
            }

    return {
        "status": "FAILED",
        "details": f"No matching DNS SAN for {hostname}.",
    }


def verify_certificate_chain(
    cert,
    hostname,
    issuer_path=None,
    roots_path=None,
):
    """Validate a server certificate against a trusted root store."""
    if not hostname:
        return {
            "status": "NOT CHECKED",
            "details": (
                "A hostname is required for server certificate chain validation."
            ),
        }

    try:
        # Use the supplied trust bundle or the default certifi bundle.
        root_path = roots_path if roots_path else certifi.where()
        trusted_roots = load_certificates(root_path)

        if not trusted_roots:
            return {
                "status": "FAILED",
                "details": "The trusted root certificate bundle is empty.",
            }

        # Load any supplied issuer/intermediate certificates.
        intermediates = []
        if issuer_path:
            intermediates = load_certificates(issuer_path)

        # PolicyBuilder requires the expected DNS name or IP address.
        try:
            subject = x509.IPAddress(ipaddress.ip_address(hostname))
        except ValueError:
            subject = x509.DNSName(hostname)

        verifier = (
            PolicyBuilder()
            .store(Store(trusted_roots))
            .build_server_verifier(subject)
        )

        verified_chain = verifier.verify(cert, intermediates)

        return {
            "status": "PASSED",
            "details": (
                "Trusted chain verified "
                f"({len(verified_chain)} certificates in verified path)."
            ),
        }

    except VerificationError as error:
        return {
            "status": "FAILED",
            "details": str(error),
        }
    except (OSError, ValueError, TypeError, NotImplementedError) as error:
        return {
            "status": "FAILED",
            "details": str(error),
        }


def get_validity_status(cert):
    """Determine whether the certificate is currently within its validity period."""
    now = datetime.now(timezone.utc)

    if now < cert.not_valid_before_utc:
        return "NOT YET VALID"

    if now > cert.not_valid_after_utc:
        return "EXPIRED"

    return "WITHIN VALIDITY DATES"


def parse_certificate(
    file_path,
    hostname=None,
    issuer_path=None,
    roots_path=None,
):
    """Parse a certificate, run validation checks, and export a JSON report."""
    path = Path(file_path)

    if not path.is_file():
        print(f"Error: File not found: {path}")
        return 1

    try:
        cert = load_certificate(path)
    except (OSError, ValueError, TypeError) as error:
        print(f"Error loading PEM certificate: {error}")
        return 1

    issuer_cert = None

    if issuer_path:
        try:
            issuer_cert = load_certificate(issuer_path)
        except (OSError, ValueError, TypeError) as error:
            print(f"Error loading issuer certificate: {error}")
            return 1

    try:
        key_details = get_public_key_details(cert.public_key())
        signature_hash = cert.signature_hash_algorithm
    except (ValueError, TypeError, NotImplementedError) as error:
        print(f"Error reading certificate details: {error}")
        return 1

    validity_status = get_validity_status(cert)

    signature_result = verify_signature(cert, issuer_cert)

    hostname_result = (
        verify_hostname(cert, hostname)
        if hostname
        else {
            "status": "NOT CHECKED",
            "details": "No hostname provided.",
        }
    )

    chain_result = verify_certificate_chain(
        cert,
        hostname,
        issuer_path,
        roots_path,
    )

    dns_names = []
    ip_addresses = []

    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value

        dns_names = san.get_values_for_type(x509.DNSName)
        ip_addresses = [
            str(address)
            for address in san.get_values_for_type(x509.IPAddress)
        ]
    except x509.ExtensionNotFound:
        pass

    print("\n===== X.509 CERTIFICATE DETAILS =====")
    print(f"File: {path.name}")
    print(f"Version: {cert.version.name}")
    print(f"Serial Number: {cert.serial_number}")
    print(f"Subject: {get_name(cert.subject)}")
    print(f"Issuer: {get_name(cert.issuer)}")

    print("\n--- Validity Period ---")
    print(f"Valid From: {cert.not_valid_before_utc}")
    print(f"Valid Until: {cert.not_valid_after_utc}")
    print(f"Status: {validity_status}")

    print("\n--- Public Key Details ---")
    for field, value in key_details.items():
        if value is not None:
            print(f"{field.replace('_', ' ').title()}: {value}")

    print("\n--- Signature ---")
    print(f"Signature Algorithm: {cert.signature_algorithm_oid._name}")
    print(
        "Signature Hash: "
        f"{signature_hash.name if signature_hash else 'Not applicable'}"
    )

    print("\n--- Subject Alternative Names ---")
    for name in dns_names:
        print(f"DNS: {name}")

    for address in ip_addresses:
        print(f"IP Address: {address}")

    if not dns_names and not ip_addresses:
        print("No DNS or IP SAN entries found.")

    print("\n--- Security Validation ---")

    validation_items = [
        ("Signature Verification", signature_result),
        ("Hostname Verification", hostname_result),
        ("Certificate Chain", chain_result),
    ]

    for label, result in validation_items:
        print(f"{label}: {result['status']} - {result['details']}")

    report = {
        "file": path.name,
        "version": cert.version.name,
        "serial_number": str(cert.serial_number),
        "subject": get_name(cert.subject),
        "issuer": get_name(cert.issuer),
        "valid_from": cert.not_valid_before_utc.isoformat(),
        "valid_until": cert.not_valid_after_utc.isoformat(),
        "validity_status": validity_status,
        "public_key": key_details,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "signature_hash": (
            signature_hash.name if signature_hash else None
        ),
        "subject_alternative_names": {
            "dns": dns_names,
            "ip_addresses": ip_addresses,
        },
        "validation": {
            "signature": signature_result,
            "hostname": hostname_result,
            "chain": chain_result,
        },
    }

    report_path = path.with_name(f"{path.stem}_report.json")

    try:
        report_path.write_text(
            json.dumps(report, indent=4),
            encoding="utf-8",
        )
        print(f"\nJSON report saved to: {report_path}")
    except OSError as error:
        print(f"Could not save JSON report: {error}")
        return 1

    # NOT CHECKED is distinct from FAILED. A check that was not requested
    # does not automatically mean that the certificate failed validation.
    validation_failed = any(
        result["status"] == "FAILED"
        for _, result in validation_items
    )

    validity_failed = validity_status != "WITHIN VALIDITY DATES"

    if validation_failed or validity_failed:
        print("\nOverall Result: FAILED")
        print("Certificate analysis completed with validation failures.")
        return 1

    print("\nOverall Result: PASSED")
    print("Certificate analysis completed.")
    return 0


if __name__ == "__main__":
    cli = argparse.ArgumentParser(
        description="X.509 Certificate Parser and Validator"
    )
    cli.add_argument(
        "certificate",
        help="Path to a PEM certificate",
    )
    cli.add_argument(
        "--hostname",
        help="Expected DNS hostname or IP address",
    )
    cli.add_argument(
        "--issuer",
        help="Optional issuer/intermediate PEM certificate",
    )
    cli.add_argument(
        "--roots",
        help="Optional trusted root PEM bundle",
    )

    args = cli.parse_args()

    exit_code = parse_certificate(
        args.certificate,
        hostname=args.hostname,
        issuer_path=args.issuer,
        roots_path=args.roots,
    )

    sys.exit(exit_code)
