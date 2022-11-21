import ed25519
import base58

def base_58_key(key: ed25519.SigningKey or ed25519.VerifyingKey):
    """Converts a key to base58"""
    return base58.b58encode(key.to_bytes()).decode('utf-8')

def format_ed25519_key(key: str):
    """Formats ed25519 key for NEAR PROTOCOL"""
    return f"ed25519:{key}"