import pytest
import os
import base64
from toolkit.symmetric import AESGCMCipher
from cryptography.exceptions import InvalidTag

def test_aes_gcm_roundtrip():
    cipher = AESGCMCipher()
    plaintext = b"Sensitive production data"
    aad = b"associated_data"
    
    encrypted = cipher.encrypt(plaintext, associated_data=aad)
    
    assert 'nonce' in encrypted
    assert 'ciphertext' in encrypted
    assert encrypted['aad'] == base64.b64encode(aad).decode('utf-8')
    
    decrypted = cipher.decrypt(encrypted, associated_data=aad)
    assert decrypted == plaintext

def test_aes_gcm_password_salt_derivation():
    salt = os.urandom(16)
    cipher1 = AESGCMCipher(password="my_secure_password", salt=salt) # nosec
    cipher2 = AESGCMCipher(password="my_secure_password", salt=salt) # nosec
    
    plaintext = b"Test message"
    encrypted = cipher1.encrypt(plaintext)
    decrypted = cipher2.decrypt(encrypted)
    
    assert decrypted == plaintext
    assert cipher1.key == cipher2.key

def test_aes_gcm_tampering():
    cipher = AESGCMCipher()
    plaintext = b"Confidential information"
    
    encrypted = cipher.encrypt(plaintext)
    
    # Tamper with the ciphertext
    raw_ct = base64.b64decode(encrypted['ciphertext'])
    tampered_ct = raw_ct[:-1] + bytes([raw_ct[-1] ^ 1])
    encrypted['ciphertext'] = base64.b64encode(tampered_ct).decode('utf-8')
    
    with pytest.raises(ValueError, match="Decryption failed"):
        cipher.decrypt(encrypted)
