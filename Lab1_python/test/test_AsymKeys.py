import rsa
import time
import unittest
import binascii

class AsymCryptoTest(unittest.TestCase):
    plain_text = "This is the plain text!"
    plain_bytes = plain_text.encode()
    ASYM_KEY_SIZE = 2048

    def test_cipher_public_decipher_private(self):
        print(f"TEST 'RSA' cipher with public, decipher with private")
        print("Text")
        print(self.plain_text)
        print("Bytes:")
        print(binascii.hexlify(self.plain_bytes))

        # generate an RSA key pair
        start_time = time.time()
        public_key, private_key = rsa.newkeys(self.ASYM_KEY_SIZE)
        print(f"Key gen: {time.time() - start_time} ms")

        print("Ciphering with public key...")
        # encrypt the plain text using the public key
        start_time = time.time()
        cipher_bytes = rsa.encrypt(self.plain_bytes, public_key)
        print(f"Encrypting: {time.time() - start_time} ms")

        print("Ciphered bytes:")
        print(binascii.hexlify(cipher_bytes))

        print("Deciphering with private key...")
        # decipher the ciphered digest using the private key
        start_time = time.time()
        deciphered_bytes = rsa.decrypt(cipher_bytes, private_key)
        print(f"Decrypting: {time.time() - start_time} ms")

        print("Deciphered bytes:")
        print(binascii.hexlify(deciphered_bytes))

        print("Text:")
        new_plain_text = deciphered_bytes.decode()
        print(new_plain_text)

        self.assertEqual(self.plain_text, new_plain_text)

if __name__ == '__main__':
    unittest.main()