package pt.ulisboa.tecnico.meic.sirs;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

public class FileIntegrityCheck {
    public static void main(String[] args) throws Exception {
        byte[] fileBytes = Files.readAllBytes(Paths.get("grades/inputs/grades.txt"));

        // Generate MAC
        SecretKeySpec keySpec = new SecretKeySpec("secretKey".getBytes(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);
        byte[] macBytes = mac.doFinal(fileBytes);
        System.out.println("MAC: " + new String(macBytes));

        // Generate digital signature
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair pair = keyPairGen.generateKeyPair();
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(pair.getPrivate());
        sign.update(fileBytes);
        byte[] signatureBytes = sign.sign();
        System.out.println("Signature: " + new String(signatureBytes));
    }
}