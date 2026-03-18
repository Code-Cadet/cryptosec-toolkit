import os
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
            'pattern': r'\bMD5\b|\bhashlib\.md5\b', # nosec
            'severity': 'CRITICAL',
            'issue': 'Broken Hash Algorithm (MD5)',
            'detail': 'MD5 is cryptographically broken and vulnerable to collision attacks.',
            'recommendation': 'Use SHA-256 or SHA-3 for integrity; Argon2id for passwords.'
        },
        {
            'id': 'SEC-002',
            'pattern': r'modes\.ECB\(\)|AES\.MODE_ECB', # nosec
            'severity': 'CRITICAL',
            'issue': 'Insecure Block Mode (ECB)',
            'detail': 'ECB mode lacks diffusion; identical plaintext blocks produce identical ciphertext.',
            'recommendation': 'Switch to AES-GCM or ChaCha20-Poly1305 for authenticated encryption.'
        },
        {
            'id': 'SEC-003',
            'pattern': r'random\.random\(\)|random\.randint\(', # nosec
            'severity': 'HIGH',
            'issue': 'Weak PRNG detected',
            'detail': 'Standard pseudo-random generators are predictable and not suitable for security.',
            'recommendation': 'Use the "secrets" module or os.urandom().'
        },
        {
            'id': 'SEC-004',
            'pattern': r'verify\s*=\s*False|CERT_NONE', # nosec
            'severity': 'CRITICAL',
            'issue': 'TLS Verification Disabled',
            'detail': 'Disabling certificate verification makes the application vulnerable to MITM attacks.',
            'recommendation': 'Ensure verify=True and provide a valid CA bundle.'
        },
        {
            'id': 'SEC-005',
            'pattern': r'password\s*=\s*["\'][^"\']{8,}["\']', # nosec
            'severity': 'HIGH',
            'issue': 'Hardcoded Credential',
            'detail': 'Hardcoded secrets in source code can be leaked via version control.',
            'recommendation': 'Use environment variables (.env) or a Secret Manager.'
        }
    ]

    @classmethod
    def audit_file(cls, file_path: str) -> List[Dict]:
        """Reads a file with fallback encoding support (UTF-8-SIG handles Windows BOM)."""
        try:
            # utf-8-sig handles files with or without the Windows 'BOM' prefix
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                content = f.read()
            return cls.scan_content(content)
        except Exception as e:
            return [{
                'severity': 'ERROR', 
                'issue': 'File Read Failure',
                'detail': str(e),
                'recommendation': 'Ensure the file is saved in UTF-8 encoding.'
            }]

    @classmethod
    def scan_content(cls, source_code: str) -> List[Dict]:
        """Scans raw string content for security vulnerabilities."""
        findings = []
        lines = source_code.splitlines()
        
        for rule in cls.SECURITY_RULES:
            for i, line in enumerate(lines):
                # Check if the pattern exists on the line
                if re.search(rule['pattern'], line, re.IGNORECASE):
                    if '# nosec' in line:
                        continue 
        
                
                    findings.append({
                        'id': rule['id'],
                        'line': i + 1,
                        'severity': rule['severity'],
                        'issue': rule['issue'],
                        'detail': rule['detail'],
                        'recommendation': rule['recommendation']
                    })
        return findings
    
    @classmethod
    def audit_environment(cls, root_dir: str = ".") -> List[Dict]:
        """Checks for the presence and safety of environment configuration files."""
        env_findings = []
        env_path = os.path.join(root_dir, ".env")
        example_path = os.path.join(root_dir, ".env.example")

        # Case 1: .env is missing but .env.example exists
        if not os.path.exists(env_path) and os.path.exists(example_path):
            env_findings.append({
                'severity': 'MEDIUM',
                'issue': 'Environment Instance Missing',
                'detail': 'Found .env.example but no .env file was detected.',
                'recommendation': 'Copy .env.example to .env and fill in your local secrets.'
            })

        # Case 2: Neither exists
        elif not os.path.exists(env_path) and not os.path.exists(example_path):
            env_findings.append({
                'severity': 'LOW',
                'issue': 'No Environment Configuration Detected',
                'detail': 'Neither .env nor .env.example files were found in the project root.',
                'recommendation': 'Implement a .env file to manage secrets securely.'
            })

        return env_findings

def run_audit(target_path: str):
    """Entry point for CLI usage."""
    print(f"--- Scanning: {target_path} ---")
    
    # 1. Run the Environment Audit first
    # We check the directory of the target path or current directory
    root_dir = os.path.dirname(os.path.abspath(target_path))
    env_results = CryptoScanner.audit_environment(root_dir)
    
    # 2. Run the File Audit
    file_results = CryptoScanner.audit_file(target_path)
    
    # Combine results
    all_results = env_results + file_results
    
    if not all_results:
        print("✅ No immediate cryptographic failures detected.")
        return

    for f in all_results:
        # Using .get() prevents KeyError if a key is missing
        severity = f.get('severity', 'UNKNOWN')
        issue = f.get('issue', 'General Issue')
        line = f.get('line', '?')
        detail = f.get('detail', 'No further details provided.')
        rec = f.get('recommendation', 'No recommendation available.')

        print(f"[{severity}] Line {line}: {issue}")
        print(f"   ↳ {detail}")
        print(f"   ↳ Recommendation: {rec}\n")

if __name__ == "__main__":
    import sys
    # If a path is provided in the terminal, scan that. Otherwise, scan itself.
    target = sys.argv[1] if len(sys.argv) > 1 else __file__
    def run_audit_with_exit(path):
        print(f"--- Scanning: {path} ---")
        results = CryptoScanner.audit_file(path)
        # Add env audit here too if needed
        root_dir = os.path.dirname(os.path.abspath(path))
        env_results = CryptoScanner.audit_environment(root_dir)
        all_results = env_results + results

        if not all_results:
            return True # Success
        
        return False # Fail

    success = run_audit_with_exit(target)
    
    # If findings were found, exit with code 1 to block Git
    if not success:
        sys.exit(1)
    else:
        sys.exit(0)