import pytest
from toolkit.scanner import CryptoScanner

def test_scanner_detects_vulnerability():
    """Verify the scanner finds a known bad pattern (MD5)."""
    bad_code = "hash = hashlib.md5(data.encode())"
    findings = CryptoScanner.scan_content(bad_code)
    
    assert len(findings) == 1
    assert findings[0]['id'] == 'SEC-001'
    assert "MD5" in findings[0]['issue']

def test_scanner_respects_nosec_bypass():
    """Verify that '# nosec' successfully silences a finding."""
    # This line has MD5 but is tagged with # nosec
    bypassed_code = "hash = hashlib.md5(data.encode()) # nosec"
    findings = CryptoScanner.scan_content(bypassed_code)
    
    # findings should be empty because of the bypass
    assert len(findings) == 0

def test_scanner_clean_code():
    """Verify that secure code produces no findings."""
    clean_code = "hash = hashlib.sha256(data.encode())"
    findings = CryptoScanner.scan_content(clean_code)
    
    assert len(findings) == 0