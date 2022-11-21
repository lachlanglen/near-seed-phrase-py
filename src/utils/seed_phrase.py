def normalize_seed_phrase(seed_phrase: str):
    """ 
        normalize seed phrase 
            - removes extra spaces
            - lowercases all words
    """
    return " ".join(map(lambda x: x.lower(), seed_phrase.strip().split(" ")))

