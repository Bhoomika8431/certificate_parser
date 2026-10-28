
# X.509 Certificate Parser and Validator

A Python project that parses X.509 certificates, displays certificate information, performs security validation checks, and exports results to a JSON report.

## Features

- Parse PEM-encoded X.509 certificates.
- Display certificate version, serial number, subject, and issuer.
- Display validity dates and current validity status.
- Extract public-key details, including algorithm and key size.
- Display signature algorithm and hash information.
- Extract DNS and IP addresses from Subject Alternative Name (SAN).
- Verify certificate signatures.
- Validate DNS hostnames and IP addresses against SAN entries.
- Validate certificate chains against trusted root certificates.
- Export certificate information and validation results to JSON.
- Return command-line exit codes for successful and failed validation.
- Run automated tests using pytest.

## Technologies

- Python
- cryptography
- certifi
- pytest

## Project Structure

```text
x509-certificate-parser/
├── parser.py
├── generate_certificate.py
├── generate_chain.py
├── tests/
│   └── test_parser.py
├── README.md
└── .gitignore
```

Generated certificates, private keys, JSON reports, and Python cache directories are created locally and are not intended to be committed.

## Requirements

- Python 3.10 or newer
- pip

## Installation on Windows

Open PowerShell in the project directory.

Create a virtual environment:

```powershell
python -m venv venv
```

Activate it:

```powershell
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install cryptography certifi pytest
```

If PowerShell prevents virtual environment activation, you can run the Python executable directly:

```powershell
.\venv\Scripts\python.exe -m pip install cryptography certifi pytest
```

## Generate Test Certificates

Generate a self-signed test certificate:

```powershell
python generate_certificate.py
```

Generate a test certificate chain containing a root CA and a server certificate:

```powershell
python generate_chain.py
```

The chain generator creates:

- `root_ca.pem` — test root CA certificate
- `root_ca_key.pem` — private key for the test root CA
- `server_certificate.pem` — server certificate signed by the test CA
- `server_key.pem` — private key for the server certificate

These are test certificates and keys, not production credentials.

## Usage

### Validate a server certificate

```powershell
python parser.py server_certificate.pem --hostname localhost --issuer root_ca.pem --roots root_ca.pem
```

The parser checks the certificate signature, hostname, and trust chain, then writes:

```text
server_certificate_report.json
```

### Test a hostname mismatch

```powershell
python parser.py server_certificate.pem --hostname example.com --issuer root_ca.pem --roots root_ca.pem
```

Because the test certificate is issued for `localhost`, the hostname check should fail for `example.com`.

### Test an untrusted root

```powershell
python parser.py server_certificate.pem --hostname localhost --issuer root_ca.pem --roots certificate.pem
```

If `certificate.pem` is not the root CA for the server certificate, chain validation should fail.

### Use the default trusted root bundle

```powershell
python parser.py server_certificate.pem --hostname localhost --issuer root_ca.pem
```

Without `--roots`, the parser uses the trusted root bundle supplied by `certifi`. The locally generated test root is not normally included in that bundle, so this test certificate's chain is expected to fail validation.

## Run Automated Tests

Run the complete test suite:

```powershell
python -m pytest -v
```

The tests cover:

1. Valid certificate and trusted chain.
2. Incorrect hostname rejection.
3. Untrusted root rejection.
4. JSON report creation and validity.
5. Missing certificate file handling.

## Exit Codes

- `0` — the parser completed and no configured validation check failed.
- `1` — a validation check failed, the certificate was invalid for its validity period, or a file/report operation failed.

A `NOT CHECKED` result means a check could not or was not performed; it should not be interpreted as proof that the certificate is safe.

## Security Notes

- Never publish private keys to a public repository.
- The generated certificates and keys are for testing only.
- A valid certificate signature alone does not establish that a certificate is trusted.
- Hostname verification, certificate validity dates, and chain validation are separate checks.
- Use trusted root certificates appropriate to the environment being validated.

## License

Add a license before distributing or reusing this project publicly.
