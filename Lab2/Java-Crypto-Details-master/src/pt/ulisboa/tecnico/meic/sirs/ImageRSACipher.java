package pt.ulisboa.tecnico.meic.sirs;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;

public class ImageRSACipher {

    public byte[] cipher(byte[] imageBytes, String publicKeyPath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(publicKeyPath));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(spec);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        int blockSize = 117;
        byte[] cipheredImageBytes = new byte[(imageBytes.length / blockSize + 1) * 128];

        int i = 0;
        int j = 0;
        while (i < imageBytes.length) {
            byte[] block = cipher.doFinal(imageBytes, i, Math.min(blockSize, imageBytes.length - i));
            System.arraycopy(block, 0, cipheredImageBytes, j, block.length);
            i += blockSize;
            j += block.length;
        }

        return cipheredImageBytes;
    }

    public static void main(String[] args) throws Exception {

        if (args.length < 3) {
            System.err.println("This program encrypts an image file with RSA.");
            System.err.println("Usage: image-rsa-cipher [inputFile.png] [publicKeyFile] [outputFile.png]");
            return;
        }

        final String inputFile = args[0];
        final String publicKeyFile = args[1];
        final String outputFile = args[2];

        ImageRSACipher cipher = new ImageRSACipher();
        byte[] cipheredImageBytes = cipher.cipher(Files.readAllBytes(Paths.get(inputFile)), publicKeyFile);
        Files.write(Paths.get(outputFile), cipheredImageBytes);

    }
}