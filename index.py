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

def CDKPriv(parent_keys, index: int):
    index += HARDENED_OFFSET
    data = bytes([0]) + parent_keys["key"] + index.to_bytes(4, "big")
    key = parent_keys["chain_code"] + data
    I = hmac.new(key=key, digestmod=hashlib.sha512).digest()
    IL = I[:32]
    IR = I[32:]
    return {
        "key": IL,
        "chain_code": IR
    }

def get_master_key_from_seed(seed: str):
    H = hmac.new(key=seed, digestmod=hashlib.sha512).digest()
    key = H[:32]
    chain_code = H[32:]
    return (key, chain_code)

def derive_path(path: str, seed: str):
    (key, chain_code) = get_master_key_from_seed(seed)
    segments = path.split("/")[1:]
    segments_list = list(map(lambda x: int(x.replace("'", '')), segments))
    return reduce(CDKPriv, segments_list, { "key": key, "chain_code": chain_code })

def generate_seed_phrase(strength=128):
    # near-seed-phrase JS library uses strength of 128, so using that as default here
    return parse_seed_phrase(mnemo.generate(strength))

def normalize_seed_phrase(seed_phrase: str):
    return " ".join(map(lambda x: x.lower(), seed_phrase.strip().split(" ")))

def base_58_key(key: ed25519.SigningKey or ed25519.VerifyingKey):
    return base58.b58encode(key.to_bytes()).decode('utf-8')

def parse_seed_phrase(seed_phrase: str, derivation_path:str=KEY_DERIVATION_PATH):
    seed = mnemo.to_seed(normalize_seed_phrase(seed_phrase))
    key = derive_path(derivation_path, seed)["key"]
    signing_key = ed25519.SigningKey(key)
    signing_key_58 = base_58_key(signing_key)
    secret_key = f"ed25519:{signing_key_58}"
    verifying_key = signing_key.get_verifying_key()
    verifying_key_58 = base_58_key(verifying_key)
    public_key = f"ed25519:{verifying_key_58}"
    return {
        "seed_phrase": seed_phrase,
        "secret_key": secret_key,
        "public_key": public_key,
    }
