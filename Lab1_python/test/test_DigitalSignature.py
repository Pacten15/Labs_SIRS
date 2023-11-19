import unittest
import rsa
import os
import binascii
import hashlib

class DigitalSignatureTest(unittest.TestCase):
    plain_text = "This is the plain text!"
    plain_bytes = plain_text.encode()
    ASYM_ALGO = "RSA"
    ASYM_KEY_SIZE = 2048
    SIGNATURE_ALGO = "SHA-256"

    def test_signature_object(self):
        nonce = os.urandom(16)
        print(f"TEST '{self.SIGNATURE_ALGO}' digital signature")

        print("Text:")
        print(self.plain_text)
        print("Bytes:")
        print(binascii.hexlify(self.plain_bytes))
        print("Nonce:")
        print(binascii.hexlify(nonce))

        # generate RSA KeyPair
        print("Generating RSA KeyPair...")
        pubkey, privkey = rsa.newkeys(self.ASYM_KEY_SIZE)

        # make digital signature
        print("Signing...")
        signature = rsa.sign(self.plain_bytes + nonce, privkey, 'SHA-256')

        # verify the signature
        print("Verifying...")
        try:
            rsa.verify(self.plain_bytes + nonce, signature, pubkey)
            print("Signature is right")
            result = True
        except rsa.VerificationError:
            print("Signature is wrong")
            result = False

        self.assertTrue(result)
    
    def test_signature_step_by_step(self):
        nonce = os.urandom(16)
        print(f"TEST step-by-step digital signature with cipher '{self.ASYM_ALGO}' and digest '{self.SIGNATURE_ALGO}'")

        print("Text:")
        print(self.plain_text)
        print("Bytes:")
        print(binascii.hexlify(self.plain_bytes))
        print("Nonce:")
        print(binascii.hexlify(nonce))

        # generate RSA KeyPair
        print("Generating RSA KeyPair...")
        pubkey, privkey = rsa.newkeys(self.ASYM_KEY_SIZE)

        # make digital signature
        print("Signing...")
        cipher_digest = self.digest_and_cipher(self.plain_bytes, pubkey, nonce)

        # verify the signature
        print("Verifying...")
        result = self.redigest_decipher_compare(cipher_digest, self.plain_bytes, privkey, nonce)
        print("Signature is " + ("right" if result else "wrong"))
        self.assertTrue(result)

    def digest_and_cipher(self, bytes, privkey, nonce):
        sha256 = hashlib.sha256()
        sha256.update(bytes)
        sha256.update(nonce)
        digest = sha256.digest()
        print("Digest:")
        print(binascii.hexlify(digest))

        cipher_digest = rsa.encrypt(digest, privkey)
        print("Cipher digest:")
        print(binascii.hexlify(cipher_digest))

        return cipher_digest

    def redigest_decipher_compare(self, received_signature, text, privkey, nonce):
        sha256 = hashlib.sha256()
        sha256.update(text)
        sha256.update(nonce)
        digest = sha256.digest()
        print("New digest:")
        print(binascii.hexlify(digest))

        deciphered_digest = rsa.decrypt(received_signature, privkey)
        print("Deciphered digest:")
        print(binascii.hexlify(deciphered_digest))

        return digest == deciphered_digest

if __name__ == '__main__':
    unittest.main()