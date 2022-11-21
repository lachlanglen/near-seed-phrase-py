# NEAR Seed Phrase

### Status: BETA, contributions welcome!

Python tool for creating and converting mnemonic-phrases, public key and private key for NEAR accounts.
#### Ported to Python from https://github.com/near/near-seed-phrase
### Install

```py
poetry add near-seed-phrase-py
```

```
poetry shell
poetry show -v // copy this virtualenv path and set it as your Python interpreter 
poetry install
```

### Usage
```py
# Generate a BIP39 seed phrase with its corresponding Keys
generate_seed_phrase()

Returns:

{
    seed_phrase: str # BIP39 seed phrase
    secret_key: str # ed25519 secret/private key, formatted for NEAR
    public_key: str # ed25519 public key, formatted for NEAR
    public_key_hex: str # lowercase hex representation of public_key that can be used as an implicit account ID; see https://docs.near.org/integrator/implicit-accounts
} 

# Recover keys from a BIP39 seed phrase (returns same response as generate_seed_phrase())
parse_seed_phrase(seed_phrase)

```




