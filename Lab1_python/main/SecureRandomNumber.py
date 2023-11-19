import secrets

class SecureRandomNumber:
    @staticmethod
    def main():
        print("Generating random byte array ...")

        array = secrets.token_bytes(32)

        print("Results: ", array.hex())

if __name__ == "__main__":
    SecureRandomNumber.main()