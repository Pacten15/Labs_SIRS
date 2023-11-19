import unittest
import hashlib
import binascii

class DigestTest(unittest.TestCase):
    plain_text = "This is the plain text!"
    plain_bytes = plain_text.encode()
    DIGEST_ALGO = "SHA-256"

    def test_digest(self):
        print(f"TEST '{self.DIGEST_ALGO}' digest")

        print("Text:")
        print(self.plain_text)
        print("Bytes:")
        print(binascii.hexlify(self.plain_bytes))

        print("Computing digest...")
        digest = hashlib.sha256(self.plain_bytes).digest()

        print("Digest:")
        digest_hex = binascii.hexlify(digest).decode()
        print(digest_hex)

        self.assertTrue("491e0b645f6d596b76529d2380b1bd96f5a1f7b83b51e64f49fd634d74cd7d15"
                        .lower() == digest_hex)

if __name__ == '__main__':
    unittest.main()