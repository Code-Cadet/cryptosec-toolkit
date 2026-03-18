# PasswordManager Logic
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

class PasswordManager:
    """Production-grade password hashing using bcrypt."""
    
    DEFAULT_ROUNDS = 12  # 2^12 iterations ≈ 0.3s/hash
    
    @staticmethod
    def hash_password(password: str, rounds: int = 12) -> str:
        """
        Hash password with bcrypt. Salt is auto-generated and embedded.
        Never store plaintext. Never use MD5/SHA-256 alone for passwords.
        """
        if len(password) > 72:
            # bcrypt silently truncates at 72 bytes — use pre-hash for longer passwords
            password = hashlib.sha256(password.encode()).hexdigest()
        
        salt = bcrypt.gensalt(rounds=rounds)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        """
        Timing-safe password verification.
        bcrypt.checkpw is already timing-safe.
        """
        if len(password) > 72:
            password = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                stored_hash.encode('utf-8')
            )
        except Exception:
            return False
    
    @staticmethod
    def needs_rehash(stored_hash: str, target_rounds: int = 12) -> bool:
        """
        Check if stored hash uses an outdated cost factor.
        Rehash on next successful login if True.
        """
        current_rounds = int(stored_hash.split('$')[2])
        return current_rounds < target_rounds

