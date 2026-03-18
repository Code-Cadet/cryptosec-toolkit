import pytest
from toolkit.asymmetric import RSACrypto

def test_rsa_encryption_roundtrip():
    crypto = RSACrypto()
    plaintext = b"symmetric_key_material"
    
    ciphertext = crypto.encrypt(plaintext)
    assert ciphertext != plaintext
    
    decrypted = crypto.decrypt(ciphertext)
    assert decrypted == plaintext

def test_rsa_signature():
    crypto = RSACrypto()
    message = b"Important transaction to sign"
    
    signature = crypto.sign(message)
    assert crypto.verify(message, signature) is True
    
    # Verify tampered message fails
    assert crypto.verify(b"Tampered transaction", signature) is False

def test_rsa_key_export_import():
    crypto1 = RSACrypto()
    password = "export_password"
    
    pem_priv = crypto1.export_private_key(password)
    pem_pub = crypto1.export_public_key()
    
    assert b"ENCRYPTED PRIVATE KEY" in pem_priv
    assert b"PUBLIC KEY" in pem_pub
    
    crypto2 = RSACrypto.import_private_key(pem_priv, password)
    
    plaintext = b"Test import message"
    ciphertext = crypto1.encrypt(plaintext)
    
    decrypted = crypto2.decrypt(ciphertext)
    assert decrypted == plaintext
    
    with pytest.raises(ValueError):
        RSACrypto.import_private_key(pem_priv, "wrong_password")
