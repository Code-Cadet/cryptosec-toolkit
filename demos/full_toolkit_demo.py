import os
import base64
from toolkit.hashing import PasswordManager
from toolkit.symmetric import AESGCMCipher
from toolkit.asymmetric import RSACrypto
from toolkit.scanner import CryptoScanner

from dotenv import load_dotenv

# Load variables from the .env file
load_dotenv()

# Securely retrieve the key with a fallback for safety
SECRET_KEY = os.getenv("SECRET_KEY", "default_insecure_key_for_dev_only")
DEBUG_MODE = os.getenv("DEBUG", "False").lower() == "true"

print(f"[*] System initialized. Debug: {DEBUG_MODE}")

def run_integrated_demo():
    print("\n" + "═"*60)
    print("AIDCONNECT INTEGRATED SECURITY TOOLKIT DEMO")
    print("═"*60)

    # ═══════════════════════════════════════════════
    # 1. USER AUTHENTICATION (Hashing)
    # ═══════════════════════════════════════════════
    print("\n[PHASE 1] User Registration & PIN Hashing")
    user_pin = SECRET_KEY
    hashed_pin = PasswordManager.hash_password(user_pin)
    print(f" -> PIN Hashed with Bcrypt: {hashed_pin[:30]}...")

    # ═══════════════════════════════════════════════
    # 2. SECURE DATA STORAGE (Symmetric)
    # ═══════════════════════════════════════════════
    print("\n[PHASE 2] Encrypting Aid Distribution Data")
    donation_data = b"RECIPIENT: Kibera Sub-County | AMOUNT: 50,000 KES | TYPE: Medical"
    salt = os.urandom(16)
    
    # We derive the key from the PIN
    cipher = AESGCMCipher(password=user_pin, salt=salt) # nosec
    encrypted_package = cipher.encrypt(donation_data, associated_data=b"TRANS_ID_001")
    print(f" -> Data encrypted via AES-256-GCM + Argon2id")
    print(f" -> Ciphertext: {encrypted_package['ciphertext'][:40]}...")

    # ═══════════════════════════════════════════════
    # 3. DIGITAL SIGNATURE (Asymmetric)
    # ═══════════════════════════════════════════════
    print("\n[PHASE 3] Signing the Transaction")
    crypto_signer = RSACrypto()
    # We sign the ENCRYPTED package to ensure authenticity
    signature = crypto_signer.sign(encrypted_package['ciphertext'].encode())
    print(" -> Digital Signature generated via RSA-PSS")

    # ═══════════════════════════════════════════════
    # 4. THE AUDIT (Scanner)
    # ═══════════════════════════════════════════════
    print("\n[PHASE 4] Self-Security Audit")
    # We run the scanner on this actual demo file
    with open(__file__, 'r', encoding='utf-8') as f:
        demo_content = f.read()
    audit_results = CryptoScanner.scan_content(demo_content)
    if not audit_results:
        print(" ✅ Static Analysis: NO cryptographic failures detected in demo logic.")
    else:
        print(f" ⚠️  Audit found {len(audit_results)} issues (check for # nosec tags).")

    # ═══════════════════════════════════════════════
    # 5. VERIFICATION
    # ═══════════════════════════════════════════════
    print("\n" + "═"*60)
    print("VERIFICATION CHECK")
    print("═"*60)
    
    # Verify Signature
    is_authentic = crypto_signer.verify(encrypted_package['ciphertext'].encode(), signature)
    # Verify PIN
    pin_correct = PasswordManager.verify_password(user_pin, hashed_pin)
    # Decrypt Data
    decrypted = cipher.decrypt(encrypted_package, associated_data=b"TRANS_ID_001")

    if is_authentic and pin_correct and decrypted == donation_data:
        print(" ✅ SUCCESS: Transaction is Authentic, PIN is Valid, and Data is Intact.")
        print(f" -> Final Payload: {decrypted.decode()}")
    else:
        print(" ❌ FAILURE: Security Integrity compromised.")

insecure_hash = "MD5" # This should trigger SEC-001

if __name__ == "__main__":
    run_integrated_demo()