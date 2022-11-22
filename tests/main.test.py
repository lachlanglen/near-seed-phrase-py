import unittest
from near_seed_phrase.main import generate_seed_phrase, parse_seed_phrase

class TestNearSeedPhrase(unittest.TestCase):


    def test_parse_seed_phrase(self):

        # parse a custom seed phrase to test
        result = parse_seed_phrase('pilot two advance cost dizzy dentist loan adult inspire observe combine crew')

        public_key = result['public_key']
        public_key_hex = result['public_key_hex']
        secret_key = result['secret_key']
        seed_phrase = result['seed_phrase']

        # assert if seed phrase is parsed correctly
        self.assertEqual(public_key, 'ed25519:FqsQH6ucSoXApb742GfKhvus1eRo5a2Jes4ZDpPvySHW')
        self.assertEqual(public_key_hex, 'dc887c1a80313a167a20b9224334247721a8c60fcce7c3f30a81f56eda57c6d1')
        self.assertEqual(secret_key, 'ed25519:q22ixmXk4RdWc9wnun8NfTpchq5jEFZTyKzYRqC2xMDWbv4EwpRNFLTQgwA3WJwKRz8dBg7thRPgck6PW68n1E8')
        self.assertEqual(seed_phrase, 'pilot two advance cost dizzy dentist loan adult inspire observe combine crew')
        

    def test_generate_seed_phrase(self):
        result = generate_seed_phrase()

        # assert all seed phrase componenets are present in the result
        self.assertTrue('public_key' in result and result['public_key'])
        self.assertTrue('public_key_hex' in result and result['public_key_hex'])
        self.assertTrue('secret_key' in result and result['secret_key'])
        self.assertTrue('seed_phrase' in result and result['seed_phrase'])

        # assert seed phrase to be 12 words
        seed_phrase = result.get('seed_phrase')
        self.assertEqual(len(seed_phrase.split(' ')), 12)


if __name__ == '__main__':
    unittest.main()
