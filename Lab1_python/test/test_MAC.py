import hashlib
import hmac
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class MACTest:
    SYM_ALGO = "AES"
    SYM_KEY_SIZE = 16  # AES key size in bytes
    MAC_ALGO = "SHA256"
    SYM_CIPHER = AES.MODE_ECB
    DIGEST_ALGO = "SHA256"
    BLOCK_SIZE = AES.block_size

    def __init__(self):
        self.plain_text = "This is the plain text!"
        self.plain_bytes = bytearray(self.plain_text.encode())

    @staticmethod
    def bytes_to_hex(b):
        return ''.join(['%02x' % byte for byte in b])

    def generate_mac_key(self):
        return secrets.token_bytes(self.SYM_KEY_SIZE)

    def make_mac(self, bytes, key):
        mac = hmac.new(key, bytes, hashlib.sha256)
        return mac.digest()

    def verify_mac(self, received_mac_bytes, bytes, key):
        mac = hmac.new(key, bytes, hashlib.sha256)
        recomputed_mac_bytes = mac.digest()
        return received_mac_bytes == recomputed_mac_bytes

    def digest_and_cipher(self, bytes, key):
        message_digest = hashlib.sha256(bytes).digest()
        cipher = AES.new(key, self.SYM_CIPHER)
        cipher_digest = cipher.encrypt(pad(message_digest, self.BLOCK_SIZE))
        return cipher_digest

    def redigest_decipher_and_compare(self, cipher_digest, bytes, key):
        message_digest = hashlib.sha256(bytes).digest()
        print(f"Message digest: {message_digest.hex()}")

        cipher = AES.new(key, self.SYM_CIPHER)
        deciphered_digest = unpad(cipher.decrypt(cipher_digest), self.BLOCK_SIZE)
        print(f"Deciphered digest: {deciphered_digest.hex()}")

        return message_digest == deciphered_digest

    def test_mac_object(self):
        print(f"TEST '{self.MAC_ALGO}' message authentication code.")
        print("Text:")
        print(self.plain_text)
        print("Bytes:")
        print(self.bytes_to_hex(self.plain_bytes))

        key = self.generate_mac_key()
        print("Signing...")
        cipher_digest = self.make_mac(self.plain_bytes, key)
        print("CipherDigest:")
        print(self.bytes_to_hex(cipher_digest))

        self.plain_bytes[0] = self.plain_bytes[1]

        print("Verifying...")
        result = self.verify_mac(cipher_digest, self.plain_bytes, key)
        print("MAC is " + ("right" if result else "wrong"))

    def test_signature_step_by_step(self):
        print(f"TEST step-by-step message authentication code using cipher '{self.SYM_CIPHER}' and digest '{self.DIGEST_ALGO}'")

        print("Text:")
        print(self.plain_text)
        print("Bytes:")
        print(self.bytes_to_hex(self.plain_bytes))

        key = self.generate_mac_key()
        print("Signing...")
        cipher_digest = self.digest_and_cipher(self.plain_bytes, key)
        print("CipherDigest:")
        print(self.bytes_to_hex(cipher_digest))

        self.plain_bytes[0] = self.plain_bytes[3]

        print("Verifying...")
        result = self.redigest_decipher_and_compare(cipher_digest, self.plain_bytes, key)
        print("MAC is " + ("right" if result else "wrong"))

if __name__ == "__main__":
    test = MACTest()
    test.test_mac_object()
    test.test_signature_step_by_step()