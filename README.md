# Comprehensive Cryptographic Toolkit

A professional-grade cryptographic toolkit providing modules for symmetric encryption, asymmetric encryption, secure hashing, and basic security auditing/scanning.

## Installation

Ensure you have Python 3.9+ installed.

1. Clone the repository:
   ```bash
   git clone <repo-url>
   cd cryptosec-toolkit
   ```

2. Create a virtual environment and activate it:
   ```bash
   python -m venv .venv
   # On Windows:
   .venv\Scripts\activate
   # On macOS/Linux:
   source .venv/bin/activate
   ```

3. Install the toolkit and development dependencies:
   ```bash
   pip install -e .[dev]
   ```

## Usage

```python
from toolkit.symmetric import encrypt_data
# ... usage examples ...
```

## Security Warnings

- **Disclaimer:** This toolkit relies on the standard `cryptography` and `bcrypt` libraries. Ensure you keep dependencies updated.
- Never commit your `.env` file or hardcoded secrets.
- Always use high-entropy random keys. This toolkit helps facilitate operations but does not substitute for a holistic organizational key management system (KMS).
