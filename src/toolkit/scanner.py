import re
from typing import List, Dict

class CryptoScanner:
    """
    A Static Analysis tool to detect insecure cryptographic patterns 
    and OWASP A02:2021 Cryptographic Failures.
    """

    # Industry-standard insecure patterns
    SECURITY_RULES = [
        {
            'id': 'SEC-001',
            'pattern': r'\bMD5\b|\bhashlib\.md5\b',
            'severity': 'CRITICAL',
            'issue': 'Broken Hash Algorithm (MD5)',
            'detail': 'MD5 is cryptographically broken and vulnerable to collision attacks.',
            'recommendation': 'Use SHA-256 or SHA-3 for integrity; Argon2id for passwords.'
        },
        {
            'id': 'SEC-002',
            'pattern': r'modes\.ECB\(\)|AES\.MODE_ECB',
            'severity': 'CRITICAL',
            'issue': 'Insecure Block Mode (ECB)',
            'detail': 'ECB mode lacks diffusion; identical plaintext blocks produce identical ciphertext.',
            'recommendation': 'Switch to AES-GCM or ChaCha20-Poly1305 for authenticated encryption.'
        },
        {
            'id': 'SEC-003',
            'pattern': r'random\.random\(\)|random\.randint\(',
            'severity': 'HIGH',
            'issue': 'Weak PRNG detected',
            'detail': 'Standard pseudo-random generators are predictable and not suitable for security.',
            'recommendation': 'Use the "secrets" module or os.urandom().'
        },
        {
            'id': 'SEC-004',
            'pattern': r'verify\s*=\s*False|CERT_NONE',
            'severity': 'CRITICAL',
            'issue': 'TLS Verification Disabled',
            'detail': 'Disabling certificate verification makes the application vulnerable to MITM attacks.',
            'recommendation': 'Ensure verify=True and provide a valid CA bundle.'
        },
        {
            'id': 'SEC-005',
            'pattern': r'password\s*=\s*["\'][^"\']{8,}["\']',
            'severity': 'HIGH',
            'issue': 'Hardcoded Credential',
            'detail': 'Hardcoded secrets in source code can be leaked via version control.',
            'recommendation': 'Use environment variables (.env) or a Secret Manager.'
        }
    ]

    @classmethod
    def audit_file(cls, file_path: str) -> List[Dict]:
        """Reads a file and returns a list of security findings."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return cls.scan_content(content)
        except Exception as e:
            return [{'severity': 'ERROR', 'issue': f'Could not read file: {str(e)}'}]

    @classmethod
    def scan_content(cls, source_code: str) -> List[Dict]:
        """Scans raw string content for security vulnerabilities."""
        findings = []
        for rule in cls.SECURITY_RULES:
            matches = re.finditer(rule['pattern'], source_code, re.IGNORECASE)
            for match in matches:
                # Find line number (count newlines before match)
                line_no = source_code.count('\n', 0, match.start()) + 1
                findings.append({
                    'id': rule['id'],
                    'line': line_no,
                    'severity': rule['severity'],
                    'issue': rule['issue'],
                    'detail': rule['detail'],
                    'recommendation': rule['recommendation']
                })
        return findings

def run_audit(target_path: str):
    """Entry point for CLI usage."""
    print(f"--- Scanning: {target_path} ---")
    results = CryptoScanner.audit_file(target_path)
    
    if not results:
        print("✅ No immediate cryptographic failures detected.")
        return

    for f in results:
        print(f"[{f['severity']}] Line {f.get('line', '?')}: {f['issue']}")
        print(f"   ↳ {f['detail']}")
        print(f"   ↳ Recommendation: {f['recommendation']}\n")

if __name__ == "__main__":
    # Example self-scan
    run_audit(__file__)