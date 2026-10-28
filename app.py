
import json
import tempfile
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

from parser import (
    get_name,
    get_public_key_details,
    get_validity_status,
    load_certificate,
    verify_certificate_chain,
    verify_hostname,
    verify_signature,
)

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB upload limit

ALLOWED_EXTENSIONS = {".pem", ".crt", ".cer"}
REPORT_DIR = Path(tempfile.gettempdir()) / "x509-parser-reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def allowed_file(filename):
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/validate")
def validate_certificate():
    certificate_file = request.files.get("certificate")
    issuer_file = request.files.get("issuer")
    roots_file = request.files.get("roots")
    hostname = request.form.get("hostname", "").strip()

    if not certificate_file or not certificate_file.filename:
        return jsonify({"error": "Please select a certificate file."}), 400

    if not allowed_file(certificate_file.filename):
        return jsonify({
            "error": "Unsupported certificate file type. Upload a PEM, CRT, or CER file."
        }), 400

    temp_paths = []

    try:
        # Save uploaded files temporarily; never execute uploaded content.
        with tempfile.NamedTemporaryFile(
            suffix=".pem", delete=False
        ) as temporary:
            certificate_file.save(temporary)
            certificate_path = Path(temporary.name)
            temp_paths.append(certificate_path)

        issuer_path = None
        if issuer_file and issuer_file.filename:
            if not allowed_file(issuer_file.filename):
                return jsonify({"error": "Unsupported issuer file type."}), 400

            with tempfile.NamedTemporaryFile(
                suffix=".pem", delete=False
            ) as temporary:
                issuer_file.save(temporary)
                issuer_path = Path(temporary.name)
                temp_paths.append(issuer_path)

        roots_path = None
        if roots_file and roots_file.filename:
            if not allowed_file(roots_file.filename):
                return jsonify({"error": "Unsupported root bundle file type."}), 400

            with tempfile.NamedTemporaryFile(
                suffix=".pem", delete=False
            ) as temporary:
                roots_file.save(temporary)
                roots_path = Path(temporary.name)
                temp_paths.append(roots_path)

        cert = load_certificate(certificate_path)

        signature_result = verify_signature(
            cert,
            load_certificate(issuer_path) if issuer_path else None,
        )

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
            hostname or None,
            str(issuer_path) if issuer_path else None,
            str(roots_path) if roots_path else None,
        )

        try:
            san = cert.extensions.get_extension_for_class(
                __import__("cryptography").x509.SubjectAlternativeName
            ).value
            dns_names = san.get_values_for_type(
                __import__("cryptography").x509.DNSName
            )
            ip_addresses = [
                str(address)
                for address in san.get_values_for_type(
                    __import__("cryptography").x509.IPAddress
                )
            ]
        except Exception as error:
            from cryptography.x509 import ExtensionNotFound

            if isinstance(error, ExtensionNotFound):
                dns_names, ip_addresses = [], []
            else:
                raise

        signature_hash = cert.signature_hash_algorithm
        validity_status = get_validity_status(cert)

        checks = {
            "signature": signature_result,
            "hostname": hostname_result,
            "chain": chain_result,
        }

        # A skipped check is not proof of successful validation.
        fully_validated = (
            validity_status == "WITHIN VALIDITY DATES"
            and all(item["status"] == "PASSED" for item in checks.values())
        )

        report = {
            "file": secure_filename(certificate_file.filename),
            "version": cert.version.name,
            "serial_number": str(cert.serial_number),
            "subject": get_name(cert.subject),
            "issuer": get_name(cert.issuer),
            "valid_from": cert.not_valid_before_utc.isoformat(),
            "valid_until": cert.not_valid_after_utc.isoformat(),
            "validity_status": validity_status,
            "public_key": get_public_key_details(cert.public_key()),
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "signature_hash": signature_hash.name if signature_hash else None,
            "subject_alternative_names": {
                "dns": dns_names,
                "ip_addresses": ip_addresses,
            },
            "validation": checks,
            "overall_status": (
                "PASSED"
                if fully_validated
                else "FAILED"
            ),
            "note": (
                "PASSED means all checks ran and passed. "
                "NOT CHECKED does not establish trust."
            ),
        }

        report_path = REPORT_DIR / "certificate_report.json"
        report_path.write_text(json.dumps(report, indent=4), encoding="utf-8")

        return jsonify({
            "report": report,
            "download_url": "/api/report",
        })

    except (OSError, ValueError, TypeError) as error:
        return jsonify({
            "error": f"Could not process certificate: {error}"
        }), 400

    finally:
        for path in temp_paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                app.logger.warning("Could not remove temporary upload file.")


@app.get("/api/report")
def download_report():
    report_path = REPORT_DIR / "certificate_report.json"

    if not report_path.is_file():
        return jsonify({"error": "No report is available. Validate a certificate first."}), 404

    return send_file(
        report_path,
        as_attachment=True,
        download_name="certificate_report.json",
        mimetype="application/json",
    )


@app.errorhandler(413)
def upload_too_large(_error):
    return jsonify({"error": "Upload is too large. Maximum size is 2 MB."}), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
