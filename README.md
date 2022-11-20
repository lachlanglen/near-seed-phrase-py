# NEAR Seed Phrase

Python tool for creating and converting mnemonic-phrases, public key and private key for NEAR accounts.

### Install
```py
pip install near-seed-phrase-py
```

### Usage
```py
# to create a seed phrase with its corresponding Keys
credentials = generateSeedPhrase()

seed_phrase = credentials["seed_phrase"]
public_key = credentials["public_key"]
private_key = credentials["private_key"]

# To recover keys from the seed phrase
keys = parseSeedPhrase(seedPhrase);

public_key = keys["public_key"]
private_key = keys["private_key"]
```