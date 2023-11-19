import unittest
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii

class SymCryptoTest(unittest.TestCase):
    plain_text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    plain_bytes = plain_text.encode()
    SYM_ALGO = "AES"
    SYM_KEY_SIZE = 16  # 128 bits
    SYM_CIPHER = "AES/ECB/PKCS5Padding"

    def test_sym_crypto(self):
        print(f"TEST '{self.SYM_CIPHER}'")

        print("Text:")
        print(self.plain_text)
        print("Bytes:")
        print(binascii.hexlify(self.plain_bytes))

        print("Generating AES key...")
        key = get_random_bytes(self.SYM_KEY_SIZE)
        print("Key: ")
        print(binascii.hexlify(key))

        cipher = AES.new(key, AES.MODE_ECB)

        print("Ciphering...")
        cipher_bytes = cipher.encrypt(pad(self.plain_bytes, AES.block_size))
        print("Result: ")
        print(binascii.hexlify(cipher_bytes))

        print("Deciphering...")
        cipher_dec = AES.new(key, AES.MODE_ECB)
        new_plain_bytes = unpad(cipher_dec.decrypt(cipher_bytes), AES.block_size)
        print("Result: ")
        print(binascii.hexlify(new_plain_bytes))

        print("Text:")
        new_plain_text = new_plain_bytes.decode()
        print(new_plain_text)

        self.assertEqual(self.plain_text, new_plain_text)

if __name__ == '__main__':
    unittest.main()