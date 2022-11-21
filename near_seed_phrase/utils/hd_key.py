import hmac
from hashlib import sha512
from functools import reduce

HARDENED_OFFSET = 0x80000000

def get_sha512_hmac(key: bytes, msg: bytes):
    """ return digest of sha512 hmac. """
    return hmac.new(key=key, msg=msg, digestmod=sha512).digest()

def cdk_priv(parent_keys, index: int):
    """ __ """
    (key, chain_code) = parent_keys
    index += HARDENED_OFFSET
    H = get_sha512_hmac(key=chain_code, msg=bytes([0]) + key + index.to_bytes(4, "big"))
    return (H[:32], H[32:])

def get_master_key_from_seed(seed: str):
    """ __ """
    H = get_sha512_hmac(key=bytes('ed25519 seed', 'utf-8'), msg=bytearray.fromhex(seed))
    return (H[:32], H[32:])

def derive_path(path: str, seed: str):
    """ __ """
    (key, chain_code) = get_master_key_from_seed(seed)
    return reduce(cdk_priv, list(map(lambda x: int(x.replace("'", '')), path.split("/")[1:])), (key, chain_code))

