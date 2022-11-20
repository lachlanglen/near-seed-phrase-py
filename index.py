# Ported to Python from https://github.com/near/near-seed-phrase

from mnemonic import Mnemonic
import ed25519
import base58
import base64
import hmac
import hashlib
from functools import reduce

import near_api

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

def hmac_sig(key):
    hmac_sig = hmac.new(key, msg=None, digestmod=hashlib.sha512)
    hmac_sig = hmac_sig.digest()
    return hmac_sig

def get_master_key_from_seed(seed: str):
    # seed = bytes('hello', 'utf-8')
    print('seed len: ', len(seed))
    print("seed: ", seed)
    # print("seed hex len: ", len(seed.hex()))
    H = hmac.new(key=bytes('ed25519 seed', 'utf-8'), msg=bytearray.fromhex(seed), digestmod=hashlib.sha512)
    print("H hex: ", H.digest().hex())
    # H.update(bytes.fromhex(seed.hex()))
    H.update(bytes('hi', 'utf-8'))
    # H = hmac.new(key=bytes('ed25519 seed', 'utf-8') + seed, digestmod=hashlib.sha512).digest()
    print("H hex 2: ", H.hexdigest())
    key = H[:32]
    chain_code = H[32:]
    return (key, chain_code)

def derive_path(path: str, seed: str):
    (key, chain_code) = get_master_key_from_seed(seed)
    print("DERIVE PATH")
    print("dp key hex: ", key.hex())
    print("dp chain_code hex: ", chain_code.hex())
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
    key = derive_path(derivation_path, seed.hex())["key"]
    print("hex derived path key: ", key.hex())
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

parsed = parse_seed_phrase("jacket blame unhappy disorder expand account frozen slide rival feature grief space lemon garbage pride huge antique century")
print("parsed: ", parsed)

public_key = parsed["public_key"]
print("hex: ", base58.b58decode(public_key.replace("ed25519:", "")).hex())

near_provider = near_api.providers.JsonProvider("https://rpc.testnet.near.org")

sender_key_pair = near_api.signer.KeyPair(parsed["secret_key"])
sender_signer = near_api.signer.Signer("lachlan100.testnet", sender_key_pair)
sender_account = near_api.account.Account(near_provider, sender_signer, "lachlan100.testnet")

out = sender_account.send_money("lachlan-nft-test-2.testnet", 1000)

print(out)