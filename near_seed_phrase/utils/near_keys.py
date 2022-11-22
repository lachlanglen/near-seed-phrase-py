from base58 import b58encode

def base_58_key_from_bytes(bytes: bytes):
    """Converts a signing key to base58"""
    return b58encode(bytes).decode('utf-8')

def format_ed25519_key(key: str):
    """Formats ed25519 key for NEAR PROTOCOL"""
    return f"ed25519:{key}"