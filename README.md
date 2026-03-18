
# CryptoSec Toolkit (AidConnect Edition)

[![Build Status](https://github.com/Code-Cadet/cryptosec-toolkit/actions/workflows/security.yml/badge.svg)](https://github.com/Code-Cadet/cryptosec-toolkit/actions/workflows/security.yml)
![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)
![MIT License](https://img.shields.io/badge/license-MIT-green)

---

**CryptoSec Toolkit (AidConnect Edition)** is a professional cryptographic library designed to secure humanitarian aid distribution for Project AidConnect, developed as a final-year Software Engineering project at USIU-Africa by Benjamin. The toolkit is engineered to defend against OWASP A02:2021 Cryptographic Failures, providing robust, modern, and auditable cryptographic primitives for mission-critical humanitarian contexts.

## Architecture Diagram

```mermaid
flowchart LR
    A[Plaintext Data] --> B[Argon2id KDF (Key Derivation)]
    B --> C[AES-256-GCM Encryption]
    C --> D[Encrypted Data]
    D --> E[RSA-2048 OAEP Encryption]
    E --> F[Digital Signature (PSS)]
    F --> G[Secure Package]
```

## Technical Deep-Dive

| Module                | Algorithm/Standard         | Rationale/Notes                                                                                 |
|-----------------------|---------------------------|-------------------------------------------------------------------------------------------------|
| Symmetric Encryption  | AES-256-GCM (AEAD)        | AEAD ensures confidentiality, integrity, and authentication. GCM is fast and widely supported.   |
| Key Derivation        | Argon2id                  | 2026 industry standard. Superior to PBKDF2/scrypt for resisting GPU/ASIC attacks.                |
| Asymmetric Encryption | RSA-2048 + OAEP           | OAEP padding prevents chosen ciphertext attacks. 2048 bits is NIST minimum for 2026.             |
| Digital Signatures    | RSA-PSS                   | PSS padding provides probabilistic, non-replayable signatures (non-repudiation).                |
| Password Hashing      | bcrypt + SHA-256 pre-hash | SHA-256 pre-hash bypasses bcrypt's 72-byte truncation. bcrypt is battle-tested for passwords.   |
| Security Scanner      | Custom SAST               | Detects MD5, ECB, hardcoded secrets. Supports `# nosec` for false-positive management.           |

**Why Argon2id over PBKDF2?**
- Argon2id is memory-hard, GPU/ASIC-resistant, and recommended by OWASP and NIST for new systems. PBKDF2 is vulnerable to hardware-accelerated brute-force attacks.

## Installation

```bash
# Clone the repository
$ git clone https://github.com/Code-Cadet/cryptosec-toolkit.git
$ cd cryptosec-toolkit

# Install in editable mode (dev)
$ pip install -e .
```

## Demo Usage

Run the full toolkit demonstration:

```bash
python demos/full_toolkit_demo.py
```

## Security Scanner (SAST)

The toolkit includes a static analysis tool to detect cryptographic anti-patterns:
- MD5 usage
- ECB mode
- Hardcoded secrets
- Supports `# nosec` to suppress false positives

## License

MIT License. See [LICENSE](LICENSE) for details.

---

**Developed by Benjamin for Project AidConnect.**
