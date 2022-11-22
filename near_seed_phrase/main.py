from mnemonic import Mnemonic
import ed25519
import base58
from utils import hd_key
from utils import near_keys
from utils import seed_phrase as seed_phrase_utils

KEY_DERIVATION_PATH = "m/44'/397'/0'"
HARDENED_OFFSET = 0x80000000

mnemo = Mnemonic("english")


def parse_seed_phrase(seed_phrase: str, derivation_path:str=KEY_DERIVATION_PATH):
    """ Parses NEAR credentials from bip39 seed phrase """
    seed = mnemo.to_seed(seed_phrase_utils.normalize_seed_phrase(seed_phrase))
    (key, _) = hd_key.derive_path(derivation_path, seed.hex())
    signing_key_raw = ed25519.SigningKey(key)
    secret_key = near_keys.format_ed25519_key(near_keys.base_58_key(signing_key_raw))
    public_key = near_keys.format_ed25519_key(near_keys.base_58_key(signing_key_raw.get_verifying_key()))
    return {
        "seed_phrase": seed_phrase,
        "secret_key": secret_key,
        "public_key": public_key,
        "public_key_hex": base58.b58decode(public_key.replace("ed25519:", "")).hex()
    }


def generate_seed_phrase(strength=128):
    """ Generates a bip39 seed phrase """
    # near-seed-phrase JS library uses strength of 128, so using that as default here
    return parse_seed_phrase(mnemo.generate(strength))


