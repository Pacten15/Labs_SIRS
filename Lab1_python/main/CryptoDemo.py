from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

class CryptoDemo:
    def __init__(self):
        self.SYM_CIPHER = "AES/ECB/PKCS5Padding"
        self.DIGEST_ALGO = "SHA-256"
        self.encodedKey = bytes([0x13, 0x45, 0x22, 0x07, 0x06, 0xF7,
                                 0xC3, 0xDD, 0x13, 0x77, 0x22, 0x07, 
                                 0xE6, 0xF2, 0x91, 0x80])

    def main(self):
        print("Welcome to the Python cryptography demonstration!")
        print("Press enter to start the demonstration")
        input()

        print("*** Symmetric cipher ***")
        print("A symmetric cipher uses a secret key to encrypt and decrypt information.")
        print("In this code we have a predefined key with this value (presented in hexadecimal notation):")
        print(self.encodedKey.hex())
        print(f"The key is {len(self.encodedKey)} bytes ({len(self.encodedKey) * 8} bits) long.")

        sentence = ""
        while not sentence.strip():
            sentence = input("Please enter a sentence to cipher: ")

        print(f"The string representation of the sentence is: \"{sentence}\"")
        plainBytes = sentence.encode()
        print(f"The binary representation of the sentence (in hexadecimal) is: {plainBytes.hex()}")
        print(f"The data is {len(plainBytes)} bytes ({len(plainBytes) * 8} bits) long")

        print("We ask Python for a cipher implementation with a provider string:")
        print(self.SYM_CIPHER)
        cipher = AES.new(self.encodedKey, AES.MODE_ECB)

        print("We initialize it for encryption with the key shown earlier.")
        print("Press enter to continue")
        input()

        print("We encrypt the data...")
        cipherBytes = cipher.encrypt(pad(plainBytes, AES.block_size))
        print(f"This is the ciphered data (in hexadecimal): {cipherBytes.hex()}")
        print(f"The data is {len(cipherBytes)} bytes ({len(cipherBytes) * 8} bits) long.")

        print("As you can see, the data is very different from the original!")
        print("You may notice an increase in data size because of padding to adjust the final data block.")
        print("Press enter to continue")
        input()

        print("We decrypt the data...")
        cipher = AES.new(self.encodedKey, AES.MODE_ECB)
        newPlainBytes = unpad(cipher.decrypt(cipherBytes), AES.block_size)

        print(f"This is the recovered data: {newPlainBytes.hex()}")
        print(f"The data is {len(newPlainBytes)} bytes ({len(newPlainBytes) * 8} bits) long.")
        print("Converted back to text:")
        newPlainText = newPlainBytes.decode()
        print(f"\"{newPlainText}\"")
        print("Press enter to continue")
        input()

        print("*** Digest ***")
        print("A message digest is a cryptographic one-way hashing function computed from an input.")
        print("Digests can be used to detect changes to a message and to build integrity protection.")
        print("We ask Python for a digest implementation with a provider string:")
        print(self.DIGEST_ALGO)
        messageDigest = SHA256.new()

        print("We now have an object that can compute a digest:")
        print(messageDigest)

        print("Press enter to continue")
        input()

        print("Again we will use the sentence:")
        print(f"\"{sentence}\"")
        print("(in hexadecimal):")
        print(plainBytes.hex())

        print("Computing digest ...")
        messageDigest.update(plainBytes)
        digest = messageDigest.digest()

        print("Digest value:")
        print(digest.hex())
        print(f"The digest is {len(digest)} bytes ({len(digest) * 8} bits) long.")

        print("For a given function, the digest output is always of the same size.")
        print("Press enter to continue")
        input()

        print("We will now make a small modification to the input:")
        sentence = "X" + sentence[1:]
        plainBytes = sentence.encode()
        print(f"\"{sentence}\"")
        print("(in hexadecimal):")
        print(plainBytes.hex())

        print("Computing digest for new sentence ...")
        messageDigest = SHA256.new()
        messageDigest.update(plainBytes)
        digest = messageDigest.digest()

        print("New digest value:")
        print(digest.hex())

        print("Notice that a small change in the text produced a big change in the digest value.")
        print("By itself, the digest does not provide protection,")
        print("but it can be combined with a secret or a cipher to produce a signature.")
        print("Press enter to conclude demonstration.")
        input()

        print("You can find more code snippets in the examples and tests:")
        print("`src/main/python` and `src/test/python`.")
        print("Have fun with Python cryptography! :)")

if __name__ == "__main__":
    CryptoDemo().main()