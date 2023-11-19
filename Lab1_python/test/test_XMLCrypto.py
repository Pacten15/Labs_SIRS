import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from xml.etree.ElementTree import Element, SubElement, tostring, fromstring

class XMLCryptoTest:
    def __init__(self):
        self.xml = "<message><body>There and Back Again</body></message>"
        self.SYM_ALGO = "AES"
        self.SYM_KEY_SIZE = 16  # AES key size in bytes
        self.SYM_CIPHER = AES.MODE_ECB

    def testXMLCrypto(self):
        print(f"TEST '{self.SYM_CIPHER}' with XML (textual) data")
        print("XML text:")
        print(self.xml)

        # parse XML document
        xmlDocument = fromstring(self.xml)

        # retrieve body text
        bodyNode = xmlDocument.find('body')
        if bodyNode is None:
            raise Exception("Body node not found!")

        plainText = bodyNode.text
        plainBytes = plainText.encode()

        print("Body text:")
        print(plainText)
        print("Bytes")
        print(plainBytes.hex())

        # remove body node
        xmlDocument.remove(bodyNode)

        # cipher body

        # generate a secret key
        key = get_random_bytes(self.SYM_KEY_SIZE)

        # get an AES cipher object and encrypt
        cipher = AES.new(key, self.SYM_CIPHER)
        cipherBytes = cipher.encrypt(pad(plainBytes, AES.block_size))
        print("Ciphered bytes:")
        print(cipherBytes.hex())

        # encoding binary data with base 64
        cipherText = base64.b64encode(cipherBytes).decode()
        print("Ciphered bytes in Base64:")
        print(cipherText)

        # create the element
        cipherBodyElement = SubElement(xmlDocument, "cipherBody")
        cipherBodyElement.text = cipherText

        print("XML document with cipher body:")
        print(tostring(xmlDocument).decode())

        # decipher body
        cipherBodyText = cipherBodyElement.text

        print("Cipher body text:")
        print(cipherBodyText)

        # decoding string in base 64
        cipherBodyBytes = base64.b64decode(cipherBodyText)
        print("Ciphered bytes: ")
        print(cipherBodyBytes.hex())

        # get an AES cipher object and decrypt
        decipher = AES.new(key, self.SYM_CIPHER)
        newPlainBytes = unpad(decipher.decrypt(cipherBodyBytes), AES.block_size)
        print("Deciphered bytes:")
        print(newPlainBytes.hex())
        newPlainText = newPlainBytes.decode()
        print("Body text:")
        print(newPlainText)

        # remove cipher body node
        xmlDocument.remove(cipherBodyElement)

        # create the element
        bodyElement = SubElement(xmlDocument, "body")
        bodyElement.text = newPlainText

        print("XML document with new body:")
        print(tostring(xmlDocument).decode())

        assert plainText == newPlainText, "Deciphered text does not match original text"

        print("\n\n")

# Run the test
if __name__ == "__main__":
    test = XMLCryptoTest()
    test.testXMLCrypto()