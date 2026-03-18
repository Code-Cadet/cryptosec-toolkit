import os
import base64
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

class AESGCMCipher:
    """
    AES-256-GCM authenticated encryption.
    Provides: Confidentiality + Integrity + Authentication
    """
    
    def __init__(self, key: Optional[bytes] = None, password: Optional[str] = None, salt: Optional[bytes] = None):
        if password and salt:
            # Argon2id Key Derivation Function
            kdf = Argon2id(
                salt=salt,
                length=32,  # 256 bits for AES
                iterations=2,
                lanes=4,
                memory_cost=65536,
            )
            self.key = kdf.derive(password.encode('utf-8'))
        else:
            self.key = key or AESGCM.generate_key(bit_length=256)
            
        self.aead = AESGCM(self.key)
    
    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> dict:
        """
        Encrypt with AES-256-GCM.
        Nonce is random 96-bit value — NEVER REUSED.
        Returns dict with nonce + ciphertext (includes 128-bit GCM tag).
        """
        nonce = os.urandom(12)   # 96 bits — GCM standard
        ciphertext = self.aead.encrypt(nonce, plaintext, associated_data)
        
        result = {
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }
        if associated_data:
            result['aad'] = base64.b64encode(associated_data).decode('utf-8')
        return result
    
    def decrypt(self, encrypted: dict, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt and verify authentication tag.
        Catches InvalidTag if ciphertext was tampered.
        """
        nonce = base64.b64decode(encrypted['nonce'])
        ciphertext = base64.b64decode(encrypted['ciphertext'])
        
        try:
            return self.aead.decrypt(nonce, ciphertext, associated_data)
        except InvalidTag:
            # Re-raise as a ValueError with a clearer message for the caller
            raise ValueError("Decryption failed: Ciphertext or authentication tag is invalid or tampered.")
