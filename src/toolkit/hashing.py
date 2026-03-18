import hashlib
import bcrypt

class PasswordManager:
    """Production-grade password hashing using bcrypt."""
    
    DEFAULT_ROUNDS = 12
    
    @staticmethod
    def hash_password(password: str, rounds: int = 12) -> str:
        if len(password.encode('utf-8')) > 72:
            password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        salt = bcrypt.gensalt(rounds=rounds)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        if len(password.encode('utf-8')) > 72:
            password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                stored_hash.encode('utf-8')
            )
        except Exception:
            return False
    
    @staticmethod
    def needs_rehash(stored_hash: str, target_rounds: int = 12) -> bool:
        try:
            current_rounds = int(stored_hash.split('$')[2])
            return current_rounds < target_rounds
        except IndexError:
            return True
