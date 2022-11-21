
# NEAR Seed Phrase

`Status: BETA, contributions welcome!`

Python tool for creating and converting mnemonic-phrases, public key and private key for NEAR accounts.
#### This is a python ported from https://github.com/near/near-seed-phrase
### Install

```py
poetry add near-seed-phrase-py
```

```
poetry shell
poetry show -v - you get your viertualenv path and you set it to the interpreter 
poetry install
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


## Used By

This project is used by the following companies:

- Few And Far


