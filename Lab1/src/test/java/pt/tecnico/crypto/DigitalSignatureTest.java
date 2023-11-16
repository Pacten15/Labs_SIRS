package pt.tecnico.crypto;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SecureRandom;

import javax.crypto.Cipher;


import org.junit.jupiter.api.Test;

/**
 * Test suite to show how the Java Security API can be used for digital
 * signatures.
 */
public class DigitalSignatureTest {

	/** Plain text to digest. */
	private final String plainText = "This is the plain text!";

	/** Asymmetric cryptography algorithm. */
	private static final String ASYM_ALGO = "RSA";
	/** Asymmetric cryptography key size. */
	private static final int ASYM_KEY_SIZE = 2048;

	/** Digital signature algorithm. */
	private static final String SIGNATURE_ALGO = "SHA256withRSA";

	/**
	 * Asymmetric cipher: combination of algorithm, block processing, and padding.
	 */
	private static final String ASYM_CIPHER = "RSA/ECB/PKCS1Padding";
	/** Digest algorithm. */
	private static final String DIGEST_ALGO = "SHA-256";


	// Nonce
     byte[] nonce = new byte[16];
     SecureRandom random = new SecureRandom();


	/**
	 * Generate a digital signature using the signature object provided by Java.
	 */
	@Test
	public void testSignatureObject() throws Exception {
        random.nextBytes(nonce);
		System.out.print("TEST '");
		System.out.print(SIGNATURE_ALGO);
		System.out.println("' digital signature");

		System.out.println("Text:");
		System.out.println(plainText);
		System.out.println("Bytes:");
		byte[] plainBytes = plainText.getBytes();
		System.out.println(printHexBinary(plainBytes));
		System.out.println("Nonce:");
		System.out.println(printHexBinary(nonce));

		// generate RSA KeyPair
		KeyPair key = generateSignatureKeyPair(ASYM_KEY_SIZE);

		// make digital signature
		System.out.println("Signing...");
		byte[] cipherDigest = makeDigitalSignature(plainBytes, key, nonce);

		// verify the signature
		System.out.println("Verifying...");
		boolean result = verifyDigitalSignature(cipherDigest, plainBytes, key, nonce);
		System.out.println("Signature is " + (result ? "right" : "wrong"));

		assertTrue(result);
	}

	/** Generates a Key Pair to use for digital signature. */
	private static KeyPair generateSignatureKeyPair(int keySize) throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ASYM_ALGO);
		keyGen.initialize(keySize);
		KeyPair key = keyGen.generateKeyPair();

		return key;
	}

	/** Calculates digital signature from text. */
	private static byte[] makeDigitalSignature(byte[] bytes, KeyPair keyPair, byte[] nonce) throws Exception {

		// get a signature object and sign the plain text with the private key
		Signature sig = Signature.getInstance(SIGNATURE_ALGO);
		sig.initSign(keyPair.getPrivate());
		sig.update(bytes);
		sig.update(nonce);
		byte[] signature = sig.sign();

		return signature;
	}

	/**
	 * Calculates new digest from text and compares it to the to deciphered digest.
	 */
	private static boolean verifyDigitalSignature(byte[] receivedSignature, byte[] bytes, KeyPair keyPair, byte[] nonce)
			throws Exception {

		// verify the signature with the public key
		Signature sig = Signature.getInstance(SIGNATURE_ALGO);
		sig.initVerify(keyPair.getPublic());
		sig.update(bytes);
		sig.update(nonce);
		try {
			return sig.verify(receivedSignature);
		} catch (SignatureException se) {
			System.err.println("Caught exception while verifying " + se);
			return false;
		}
	}

	/**
	 * Generate a digital signature by performing all the steps separately (for
	 * illustration purposes). It is better to use the Signature object in
	 * applications.
	 */
	@Test
	public void testSignatureStepByStep() throws Exception {
        random.nextBytes(nonce);
		System.out.print("TEST step-by-step digital signature with cipher '");
		System.out.print(ASYM_CIPHER);
		System.out.print("' and digest '");
		System.out.print(DIGEST_ALGO);
		System.out.println("'");

		System.out.println("Text:");
		System.out.println(plainText);
		System.out.println("Bytes:");
		byte[] plainBytes = plainText.getBytes();
		System.out.println(printHexBinary(plainBytes));
		System.out.println("Nonce:");
		System.out.println(printHexBinary(nonce));

		// generate RSA KeyPair
		KeyPair key = generateSignatureKeyPair(ASYM_KEY_SIZE);

		// make digital signature
		System.out.println("Signing...");
		byte[] cipherDigest = digestAndCipher(plainBytes, key, nonce);

		// verify the signature
		System.out.println("Verifying...");
		boolean result = redigestDecipherCompare(cipherDigest, plainBytes, key, nonce);
		System.out.println("Signature is " + (result ? "right" : "wrong"));
		assertTrue(result);

	}

	/** auxiliary method to calculate digest from text and cipher it */
	private static byte[] digestAndCipher(byte[] bytes, KeyPair keyPair, byte[] nonce) throws Exception {

		// get a message digest object using the specified algorithm
		MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGO);

		// calculate the digest and print it out
		messageDigest.update(bytes);
		messageDigest.update(nonce);
		byte[] digest = messageDigest.digest();
		System.out.println("Digest:");
		System.out.println(printHexBinary(digest));

		// get an RSA cipher object
		Cipher cipher = Cipher.getInstance(ASYM_CIPHER);

		// encrypt the plain text using the private key
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		byte[] cipherDigest = cipher.doFinal(digest);

		System.out.println("Cipher digest:");
		System.out.println(printHexBinary(cipherDigest));

		return cipherDigest;
	}

	/**
	 * auxiliary method to calculate new digest from text and compare it to the to
	 * deciphered digest
	 */
	private static boolean redigestDecipherCompare(byte[] receivedSignature, byte[] text, KeyPair keyPair, byte[] nonce)
			throws Exception {

		// get a message digest object
		MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGO);

		// calculate the digest and print it out

		messageDigest.update(text);
		messageDigest.update(nonce);
		byte[] digest = messageDigest.digest();
		System.out.println("New digest:");
		System.out.println(printHexBinary(digest));

		// get a cipher object
		Cipher cipher = Cipher.getInstance(ASYM_CIPHER);

		// decipher the ciphered digest using the public key
		cipher.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
		byte[] decipheredDigest = cipher.doFinal(receivedSignature);
		System.out.println("Deciphered digest:");
		System.out.println(printHexBinary(decipheredDigest));

		// compare digests
		if (digest.length != decipheredDigest.length)
			return false;

		for (int i = 0; i < digest.length; i++)
			if (digest[i] != decipheredDigest[i])
				return false;
		return true;
	}

}
