from mnemonic import Mnemonic
from nacl.signing import SigningKey
from base58 import b58decode
from near_seed_phrase.utils.hd_key import derive_path
from near_seed_phrase.utils.near_keys import format_ed25519_key, base_58_signing_key, base_58_verify_key
from near_seed_phrase.utils.seed_phrase import normalize_seed_phrase

KEY_DERIVATION_PATH = "m/44'/397'/0'"
HARDENED_OFFSET = 0x80000000

mnemo = Mnemonic("english")

def parse_seed_phrase(seed_phrase: str, derivation_path:str=KEY_DERIVATION_PATH):
    """ Parses NEAR credentials from bip39 seed phrase """
    seed = mnemo.to_seed(normalize_seed_phrase(seed_phrase))
    (key, _) = derive_path(derivation_path, seed.hex())
    signing_key = SigningKey(key)
    verify_key = signing_key.verify_key
    secret_key = format_ed25519_key(base_58_signing_key(signing_key))
    public_key = format_ed25519_key(base_58_verify_key(verify_key))
    return {
        "seed_phrase": seed_phrase,
        "secret_key": secret_key,
        "public_key": public_key,
        "public_key_hex": b58decode(public_key.replace("ed25519:", "")).hex()
    }


def generate_seed_phrase(strength=128):
    """ Generates a bip39 seed phrase """
    # near-seed-phrase JS library uses strength of 128, so using that as default here
    return parse_seed_phrase(mnemo.generate(strength))
