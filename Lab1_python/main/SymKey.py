from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys

class SymKey:
    SYM_ALGO = AES
    SYM_KEY_SIZE = 16  # AES key size is 16 bytes (128 bits)

    @staticmethod
    def main():
        if len(sys.argv) < 3:
            print("args: (r/w) (key-file)")
            return

        mode = sys.argv[1]
        key_path = sys.argv[2]

        if mode.startswith("w"):
            print("Generate and save key")
            SymKey.write(key_path)
        else:
            print("Load key")
            SymKey.read(key_path)

        print("Done.")

    @staticmethod
    def write(key_path):
        print(f"Generating {SymKey.SYM_ALGO.__name__} key ...")
        key = get_random_bytes(SymKey.SYM_KEY_SIZE)
        print(f"{SymKey.SYM_KEY_SIZE * 8} bits")
        print("Finish generating key")

        encoded = key.hex()
        print("Key:")
        print(encoded)

        print(f"Writing key to '{key_path}' ...")
        with open(key_path, 'w') as key_file:
            key_file.write(encoded)

    @staticmethod
    def read(key_path):
        print(f"Reading key from file {key_path} ...")
        with open(key_path, 'r') as key_file:
            encoded = key_file.read()

        print("Key:")
        print(encoded)

        key = bytes.fromhex(encoded)

        return key

if __name__ == "__main__":
    SymKey.main()