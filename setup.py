from setuptools import setup, find_packages

META_DATA = dict(
    name="near-seed-phrase-py",
    version="0.1.0",
    license="MIT",

    author="Lachlan Glen",

    url="https://github.com/lachlanglen/near-seed-phrase-py",

    packages=find_packages(),

    install_requires=["mnemonic", "base58", "ed25519"]
)

if __name__ == "__main__":
    setup(**META_DATA)