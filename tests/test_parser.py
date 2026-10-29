
import json
import subprocess
import sys
from pathlib import Path

import pytest


PROJECT_DIR = Path(__file__).resolve().parent.parent
PARSER_SCRIPT = PROJECT_DIR / "parser.py"
GENERATOR_SCRIPT = PROJECT_DIR / "generate_chain.py"


@pytest.fixture(scope="module", autouse=True)
def generate_test_certificates():
    """Generate fresh certificates for the test suite."""
    result = subprocess.run(
        [sys.executable, str(GENERATOR_SCRIPT)],
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, (
        "Certificate generation failed.\n"
        f"STDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}"
    )


def run_parser(*arguments):
    """Run parser.py and return the completed process."""
    return subprocess.run(
        [sys.executable, str(PARSER_SCRIPT), *arguments],
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True,
    )


def test_valid_certificate_and_chain():
    """A valid certificate and trusted chain should pass."""
    result = run_parser(
        "server_certificate.pem",
        "--hostname", "localhost",
        "--issuer", "root_ca.pem",
        "--roots", "root_ca.pem",
    )

    assert result.returncode == 0, (
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    assert "Signature Verification: PASSED" in result.stdout
    assert "Hostname Verification: PASSED" in result.stdout
    assert "Certificate Chain: PASSED" in result.stdout
    assert "Overall Result: PASSED" in result.stdout


def test_wrong_hostname_is_rejected():
    """A wrong hostname fails without invalidating a trusted chain."""
    result = run_parser(
        "server_certificate.pem",
        "--hostname", "example.com",
        "--issuer", "root_ca.pem",
        "--roots", "root_ca.pem",
    )

    assert result.returncode == 1, (
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    assert "Signature Verification: PASSED" in result.stdout
    assert "Hostname Verification: FAILED" in result.stdout
    assert "Certificate Chain: PASSED" in result.stdout
    assert "Overall Result: FAILED" in result.stdout


def test_untrusted_root_is_rejected():
    """A certificate issued by an untrusted CA should fail chain validation."""
    result = run_parser(
        "server_certificate.pem",
        "--hostname", "localhost",
        "--issuer", "root_ca.pem",
        "--roots", "certificate.pem",
    )

    assert result.returncode == 1, (
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    assert "Signature Verification: PASSED" in result.stdout
    assert "Hostname Verification: PASSED" in result.stdout
    assert "Certificate Chain: FAILED" in result.stdout
    assert "Overall Result: FAILED" in result.stdout


def test_json_report_is_valid():
    """The parser should produce a readable JSON report."""
    result = run_parser(
        "server_certificate.pem",
        "--hostname", "localhost",
        "--issuer", "root_ca.pem",
        "--roots", "root_ca.pem",
    )

    assert result.returncode == 0, (
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )

    report_path = PROJECT_DIR / "server_certificate_report.json"
    assert report_path.is_file()

    with report_path.open("r", encoding="utf-8") as report_file:
        report = json.load(report_file)

    assert report["file"] == "server_certificate.pem"
    assert report["validity_status"] == "WITHIN VALIDITY DATES"
    assert report["validation"]["signature"]["status"] == "PASSED"
    assert report["validation"]["hostname"]["status"] == "PASSED"
    assert report["validation"]["chain"]["status"] == "PASSED"


def test_missing_certificate_file():
    """A missing certificate file should return a nonzero exit code."""
    result = run_parser("does_not_exist.pem")

    assert result.returncode == 1
    assert "File not found" in result.stdout
