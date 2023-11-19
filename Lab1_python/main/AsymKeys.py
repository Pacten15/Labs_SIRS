from Crypto.PublicKey import RSA
from Crypto.IO import PEM

def write(public_key_path, private_key_path):
    # generate key pair
    key = RSA.generate(2048)

    print("Public key info:")
    print(f"algorithm: {key.publickey()}")
    print(f"format: {key.publickey().format('PEM')}")

    print(f"Writing public key to {public_key_path} ...")
    pub_key = key.publickey().export_key(format='PEM')
    with open(public_key_path, 'wb') as pub_file:
        pub_file.write(pub_key)

    print("---")

    print("Private key info:")
    print(f"algorithm: {key}")
    print(f"format: {key.format()}")

    print(f"Writing private key to {private_key_path} ...")
    priv_key = key.export_key(format='PEM')
    with open(private_key_path, 'wb') as priv_file:
        priv_file.write(priv_key)

def read(public_key_path, private_key_path):
    print(f"Reading public key from file {public_key_path} ...")
    with open(public_key_path, 'rb') as pub_file:
        pub_key = RSA.import_key(pub_file.read())

    print(pub_key)

    print("---")

    print(f"Reading private key from file {private_key_path} ...")
    with open(private_key_path, 'rb') as priv_file:
        priv_key = RSA.import_key(priv_file.read())

    print("---")

    return RSA.construct((pub_key, priv_key))

# Example usage:
mode = input("Choose mode (r/w): ")
public_key_file = input("Enter public key file path: ")
private_key_file = input("Enter private key file path: ")

if mode.startswith('w'):
    print("Generate and save keys")
    write(public_key_file, private_key_file)
else:
    print("Load keys")
    key_pair = read(public_key_file, private_key_file)

print("Done.")