
import argparse
import ipaddress
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import certifi
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed25519,
    ed448,
    padding,
    rsa,
)
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError


def get_name(name):
    """Return a readable X.509 distinguished name."""
    return name.rfc4514_string() if name else "Not available"


def get_public_key_details(cert):
    """Return public-key information for display."""
    key = cert.public_key()
    result = {
        "type": type(key).__name__,
        "algorithm": type(key).__name__,
    }
    if hasattr(key, "key_size"):
        result["key_size"] = key.key_size
    return result


def load_certificate(path):
    """Load a single PEM or DER certificate."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    data = path.read_bytes()
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        try:
            return x509.load_der_x509_certificate(data)
        except ValueError as exc:
            raise ValueError(
                "Invalid certificate file or unsupported format."
            ) from exc


def load_certificates(path):
    """Load certificates from a PEM bundle or a DER certificate."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    data = path.read_bytes()
    marker = b"-----BEGIN CERTIFICATE-----"
    end_marker = b"-----END CERTIFICATE-----"

    if marker not in data:
        try:
            return [x509.load_der_x509_certificate(data)]
        except ValueError as exc:
            raise ValueError("Invalid certificate file.") from exc

    certificates = []
    remaining = data

    while marker in remaining:
        start = remaining.find(marker)
        end = remaining.find(end_marker, start)

        if end == -1:
            raise ValueError("Invalid PEM certificate bundle.")

        end += len(end_marker)
        certificates.append(
            x509.load_pem_x509_certificate(remaining[start:end])
        )
        remaining = remaining[end:]

    if not certificates:
        raise ValueError("No certificates found in the file.")

    return certificates


def verify_signature(cert, issuer_path=None):
    """Verify a certificate signature using its issuer public key."""
    try:
        if isinstance(issuer_path, (str, Path)):
            issuers = load_certificates(issuer_path)
            issuer = next(
                (item for item in issuers if item.subject == cert.issuer),
                None,
            )
        elif issuer_path is not None:
            issuer = (
                issuer_path
                if issuer_path.subject == cert.issuer
                else None
            )
        else:
            issuer = cert if cert.subject == cert.issuer else None

        if issuer is None:
            return {
                "status": "FAILED",
                "details": "Issuer certificate was not provided or does not match.",
            }

        key = issuer.public_key()
        algorithm = cert.signature_hash_algorithm

        if isinstance(key, rsa.RSAPublicKey):
            if cert.signature_algorithm_oid.dotted_string == "1.2.840.113549.1.1.10":
                key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(algorithm),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    algorithm,
                )
            else:
                key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    algorithm,
                )
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(algorithm),
            )
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            return {
                "status": "NOT CHECKED",
                "details": "Unsupported public-key algorithm.",
            }

        return {
            "status": "PASSED",
            "details": "Certificate signature is valid.",
        }

    except (OSError, ValueError, TypeError, Exception) as exc:
        return {"status": "FAILED", "details": str(exc)}


def verify_hostname(cert, hostname):
    """Verify the requested DNS name or IP against Subject Alternative Name."""
    if not hostname:
        return {"status": "NOT CHECKED", "details": "No hostname provided."}

    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        return {
            "status": "FAILED",
            "details": "Certificate has no subjectAltName extension.",
        }

    try:
        requested_ip = ipaddress.ip_address(hostname)
    except ValueError:
        requested_ip = None

    if requested_ip is not None:
        matches = requested_ip in san.get_values_for_type(x509.IPAddress)
    else:
        requested = hostname.rstrip(".").lower()
        dns_names = san.get_values_for_type(x509.DNSName)
        matches = any(
            requested == name.rstrip(".").lower()
            or (
                name.startswith("*.")
                and requested.endswith(name[1:].lower())
                and requested.count(".") == name.count(".")
            )
            for name in dns_names
        )

    if matches:
        return {
            "status": "PASSED",
            "details": f"Certificate matches hostname {hostname}.",
        }

    return {
        "status": "FAILED",
        "details": f"No matching DNS SAN or IP SAN for {hostname}.",
    }


def verify_certificate_chain(
    cert,
    hostname,
    issuer_path=None,
    roots_path=None,
):
    """Verify the certificate against a trusted root store."""
    try:
        root_path = roots_path or certifi.where()
        trusted_roots = load_certificates(root_path)

        if not trusted_roots:
            return {
                "status": "FAILED",
                "details": "Trusted root bundle is empty.",
            }

        intermediates = []
        if issuer_path:
            if isinstance(issuer_path, (str, Path)):
                intermediates = load_certificates(issuer_path)
            else:
                intermediates = [issuer_path]

        # Keep hostname matching separately reportable.
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        dns_names = san.get_values_for_type(x509.DNSName)
        ip_names = san.get_values_for_type(x509.IPAddress)

        if dns_names:
            identity = x509.DNSName(dns_names[0])
        elif ip_names:
            identity = x509.IPAddress(ip_names[0])
        else:
            return {
                "status": "FAILED",
                "details": "Certificate has no DNS or IP subjectAltName.",
            }

        verifier = (
            PolicyBuilder()
            .store(Store(trusted_roots))
            .build_server_verifier(identity)
        )
        verified_chain = verifier.verify(cert, intermediates)

        return {
            "status": "PASSED",
            "details": (
                "Trusted chain verified "
                f"({len(verified_chain)} certificates in verified path)."
            ),
        }

    except FileNotFoundError:
        raise
    except Exception as exc:
        return {"status": "FAILED", "details": str(exc)}


def get_validity_status(cert):
    """Return the certificate validity state."""
    not_before = getattr(cert, "not_valid_before_utc", None)
    not_after = getattr(cert, "not_valid_after_utc", None)

    if not_before is None:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    if not_after is None:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)

    if now < not_before:
        return "NOT YET VALID"
    if now > not_after:
        return "EXPIRED"
    return "WITHIN VALIDITY DATES"


def certificate_details(cert):
    """Collect certificate details for the JSON report."""
    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        dns_names = san.get_values_for_type(x509.DNSName)
        ip_addresses = [
            str(value) for value in san.get_values_for_type(x509.IPAddress)
        ]
    except x509.ExtensionNotFound:
        dns_names = []
        ip_addresses = []

    not_before = getattr(cert, "not_valid_before_utc", None)
    not_after = getattr(cert, "not_valid_after_utc", None)

    if not_before is None:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    if not_after is None:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    return {
        "subject": get_name(cert.subject),
        "issuer": get_name(cert.issuer),
        "serial_number": str(cert.serial_number),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "signature_algorithm": (
            cert.signature_hash_algorithm.name
            if cert.signature_hash_algorithm
            else "Unknown"
        ),
        "public_key": get_public_key_details(cert),
        "dns_names": dns_names,
        "ip_addresses": ip_addresses,
    }


def main():
    cli = argparse.ArgumentParser(
        description="X.509 Certificate Parser and Validator"
    )
    cli.add_argument("certificate", help="Certificate file path")
    cli.add_argument("--hostname", help="Expected hostname or IP address")
    cli.add_argument("--issuer", help="Issuer or intermediate certificate")
    cli.add_argument("--roots", help="Trusted root certificate or PEM bundle")
    args = cli.parse_args()

    try:
        cert = load_certificate(args.certificate)

        signature = verify_signature(cert, args.issuer)
        hostname = verify_hostname(cert, args.hostname)
        chain = verify_certificate_chain(
            cert, args.hostname, args.issuer, args.roots
        )
        validity = get_validity_status(cert)

        results = {
            "signature": signature,
            "hostname": hostname,
            "chain": chain,
        }
        passed = (
            validity == "WITHIN VALIDITY DATES"
            and all(item["status"] == "PASSED" for item in results.values())
        )

        report = {
            "file": Path(args.certificate).name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "validity_status": validity,
            "certificate_details": certificate_details(cert),
            "validation": results,
            "overall_result": "PASSED" if passed else "FAILED",
        }

        report_path = Path(args.certificate).with_name(
            f"{Path(args.certificate).stem}_report.json"
        )
        report_path.write_text(
            json.dumps(report, indent=4),
            encoding="utf-8",
        )

        print("\n========== X.509 CERTIFICATE VALIDATION ==========")
        print(f"Certificate: {args.certificate}")
        print(f"Validity: {validity}")
        print(f"Signature Verification: {signature['status']}")
        print(f"  Details: {signature['details']}")
        print(f"Hostname Verification: {hostname['status']}")
        print(f"  Details: {hostname['details']}")
        print(f"Certificate Chain: {chain['status']}")
        print(f"  Details: {chain['details']}")
        print(f"Overall Result: {'PASSED' if passed else 'FAILED'}")
        print(f"JSON Report: {report_path}")
        print("\nCertificate Details")
        print(f"  Subject: {get_name(cert.subject)}")
        print(f"  Issuer: {get_name(cert.issuer)}")
        print(f"  Serial Number: {cert.serial_number}")
        print(f"  DNS SANs: {', '.join(certificate_details(cert)['dns_names']) or 'None'}")
        print(f"  IP SANs: {', '.join(certificate_details(cert)['ip_addresses']) or 'None'}")

        return 0 if passed else 1

    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"Error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
