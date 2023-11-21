package pt.ulisboa.tecnico.meic.sirs;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.PrivateKey;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class ImageRSADecipher {

    public byte[] decipher(byte[] cipheredImageBytes, String privateKeyPath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(privateKeyPath));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(spec);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        int blockSize = 128;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (int i = 0; i < cipheredImageBytes.length; i += blockSize) {
            byte[] block = cipher.doFinal(cipheredImageBytes, i, blockSize);
            baos.write(block);
        }

        byte[] decipheredImageBytes = baos.toByteArray();
        
        return decipheredImageBytes;

    }

    public static void main(String[] args) throws Exception {

        if (args.length < 3) {
            System.err.println("This program encrypts an image file with RSA.");
            System.err.println("Usage: image-rsa-cipher [inputFile.png] [privateKeyFile] [outputFile.png]");
            return;
        }

        final String inputFile = args[0];
        final String privateKeyFile = args[1];
        final String outputFile = args[2];

        ImageRSADecipher cipher = new ImageRSADecipher();
        byte[] cipheredImageBytes = cipher.decipher(Files.readAllBytes(Paths.get(inputFile)), privateKeyFile);
        Files.write(Paths.get(outputFile), cipheredImageBytes);

    }
}

