# AES-GCM Logic
import os
import hmac
import hashlib
import secrets
import base64
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import bcrypt

class AESGCMCipher:
    """
    AES-256-GCM authenticated encryption.
    Provides: Confidentiality + Integrity + Authentication
    """
    
    def __init__(self, key: Optional[bytes] = None):
        self.key = key or AESGCM.generate_key(bit_length=256)
        self.aead = AESGCM(self.key)
    
    def encrypt(self, plaintext: bytes, 
                associated_data: Optional[bytes] = None) -> dict:
        """
        Encrypt with AES-256-GCM.
        Nonce is random 96-bit value — NEVER REUSED.
        Returns dict with nonce + ciphertext (includes 128-bit GCM tag).
        """
        nonce = os.urandom(12)   # 96 bits — GCM standard
        ciphertext = self.aead.encrypt(nonce, plaintext, associated_data)
        return {
            'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'aad': base64.b64encode(associated_data).decode() 
                   if associated_data else None
        }
    
    def decrypt(self, encrypted: dict, 
                associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt and verify authentication tag.
        Raises InvalidTag if ciphertext was tampered.
        """
        nonce = base64.b64decode(encrypted['nonce'])
        ciphertext = base64.b64decode(encrypted['ciphertext'])
        
        # This raises cryptography.exceptions.InvalidTag if tampered
        return self.aead.decrypt(nonce, ciphertext, associated_data)
