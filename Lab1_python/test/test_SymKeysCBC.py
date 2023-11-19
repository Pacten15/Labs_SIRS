import unittest
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from binascii import hexlify

class SymCryptoTest(unittest.TestCase):
    plain_text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    plain_bytes = plain_text.encode()
    SYM_ALGO = "AES"
    SYM_KEY_SIZE = 16  # 128 bits
    SYM_CIPHER = "AES/CBC/PKCS5Padding"

    def test_sym_crypto(self):
        print(f"TEST '{self.SYM_CIPHER}'")

        print("Text:")
        print(self.plain_text)
        print("Bytes:")
        print(hexlify(self.plain_bytes))

        print("Generating AES key...")
        start_time = time.time()
        key = get_random_bytes(self.SYM_KEY_SIZE)
        print(f"Key gen: {time.time() - start_time} ms")
        print("Key: ")
        print(hexlify(key))

        iv = get_random_bytes(AES.block_size)
        print("IV:  ")
        print(hexlify(iv))

        cipher = AES.new(key, AES.MODE_CBC, iv)

        print("Ciphering...")
        start_time = time.time()
        cipher_bytes = cipher.encrypt(self.plain_bytes)
        print(f"Encrypt: {time.time() - start_time} ms")
        print("Result: ")
        print(hexlify(cipher_bytes))

        print("Deciphering...")
        cipher_dec = AES.new(key, AES.MODE_CBC, iv)
        start_time = time.time()
        new_plain_bytes = cipher_dec.decrypt(cipher_bytes)
        print(f"Decrypt: {time.time() - start_time} ms")
        print("Result: ")
        print(hexlify(new_plain_bytes))

        print("Text:")
        new_plain_text = new_plain_bytes.decode().rstrip('\x00')
        print(new_plain_text)

        self.assertEqual(self.plain_text, new_plain_text)

if __name__ == '__main__':
    unittest.main()