# Ported to Python from https://github.com/near/near-seed-phrase

from mnemonic import Mnemonic
import ed25519
import base58
import hmac
import hashlib
from functools import reduce

KEY_DERIVATION_PATH = "m/44'/397'/0'"
HARDENED_OFFSET = 0x80000000

mnemo = Mnemonic("english")

def get_sha512_hmac(key: bytes, msg: bytes):
    return hmac.new(key=key, msg=msg, digestmod=hashlib.sha512).digest()

def CDKPriv(parent_keys, index: int):
    (key, chain_code) = parent_keys
    index += HARDENED_OFFSET
    H = get_sha512_hmac(key=chain_code, msg=bytes([0]) + key + index.to_bytes(4, "big"))
    return (H[:32], H[32:])

def get_master_key_from_seed(seed: str):
    H = get_sha512_hmac(key=bytes('ed25519 seed', 'utf-8'), msg=bytearray.fromhex(seed))
    return (H[:32], H[32:])

def derive_path(path: str, seed: str):
    (key, chain_code) = get_master_key_from_seed(seed)
    return reduce(CDKPriv, list(map(lambda x: int(x.replace("'", '')), path.split("/")[1:])), (key, chain_code))

def generate_seed_phrase(strength=128):
    # near-seed-phrase JS library uses strength of 128, so using that as default here
    return parse_seed_phrase(mnemo.generate(strength))

def normalize_seed_phrase(seed_phrase: str):
    return " ".join(map(lambda x: x.lower(), seed_phrase.strip().split(" ")))

def base_58_key(key: ed25519.SigningKey or ed25519.VerifyingKey):
    return base58.b58encode(key.to_bytes()).decode('utf-8')

def format_ed25519_key(key: str):
    return f"ed25519:{key}"

def parse_seed_phrase(seed_phrase: str, derivation_path:str=KEY_DERIVATION_PATH):
    seed = mnemo.to_seed(normalize_seed_phrase(seed_phrase))
    (key, _) = derive_path(derivation_path, seed.hex())
    signing_key_raw = ed25519.SigningKey(key)
    secret_key = format_ed25519_key(base_58_key(signing_key_raw))
    public_key = format_ed25519_key(base_58_key(signing_key_raw.get_verifying_key()))
    return {
        "seed_phrase": seed_phrase,
        "secret_key": secret_key,
        "public_key": public_key,
    }

print(generate_seed_phrase())