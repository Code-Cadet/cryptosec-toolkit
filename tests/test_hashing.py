import pytest
from toolkit.hashing import PasswordManager

def test_password_hashing():
    password = "SuperSecretPassword123"
    hashed = PasswordManager.hash_password(password, rounds=4)  # 4 for faster tests
    
    assert PasswordManager.verify_password(password, hashed) is True
    assert PasswordManager.verify_password("wrong_password", hashed) is False

def test_password_truncation_handling():
    long_password_1 = "A" * 73 + "1"
    long_password_2 = "A" * 73 + "2"
    
    hashed = PasswordManager.hash_password(long_password_1, rounds=4)
    
    assert PasswordManager.verify_password(long_password_1, hashed) is True
    assert PasswordManager.verify_password(long_password_2, hashed) is False

def test_needs_rehash():
    # Mocking an old hash with 10 rounds
    old_hash = "$2b$10$R9h/lSAbV3mS3.8R9jR9XO9XO9XO9XO9XO9XO9XO9XO9XO9XO9XO"
    assert PasswordManager.needs_rehash(old_hash, target_rounds=12) is True
    
    # Mocking a new hash with 14 rounds
    new_hash = "$2b$14$R9h/lSAbV3mS3.8R9jR9XO9XO9XO9XO9XO9XO9XO9XO9XO9XO9XO"
    assert PasswordManager.needs_rehash(new_hash, target_rounds=12) is False
