package pt.tecnico;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

/**
 * Example of JSON writer.
 */
public class SecureWriter {
    public static void main(String[] args) throws Exception {
        // Check arguments
        if (args.length < 1) {
            System.err.println("Argument(s) missing!");
            System.err.printf("Usage: java %s file%n", SecureWriter.class.getName());
            return;
        }
        final String filename = args[0];

        // Load the private key
        PrivateKey privateKey = readPrivateKey(args[1]);

        //create nonce
        byte[] nonce = new byte[16];
        SecureRandom random = new SecureRandom();

        random.nextBytes(nonce);


        // Create bank statement JSON object
        JsonObject jsonObject = new JsonObject();

        JsonObject headerObject = new JsonObject();
        headerObject.addProperty("author", "Ultrn");
        headerObject.addProperty("version", 2);
        headerObject.addProperty("title", "Age of Ultron");
        JsonArray tagsArray = new JsonArray();
        tagsArray.add("robot");
        tagsArray.add("autonomy");
        headerObject.add("tags", tagsArray);
        jsonObject.add("header", headerObject);

        jsonObject.addProperty("body", "I had strings but now I'm free");
        jsonObject.addProperty("status", "published");

         // Convert the JSON object to a byte array
         String jsonString = jsonObject.toString();
         byte[] documentBytes = jsonString.getBytes();

        // Generate the digital signature
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(documentBytes);
        signature.update(nonce);
        byte[] signatureBytes = signature.sign();

        // Add the signature to the JSON object
        jsonObject.addProperty("signature", Base64.getEncoder().encodeToString(signatureBytes));

        // Add the current timestamp as a freshness token
        jsonObject.addProperty("timestamp", System.currentTimeMillis());

        // Write JSON object to file
        try (FileWriter fileWriter = new FileWriter(filename)) {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            gson.toJson(jsonObject, fileWriter);
        }

        // Write nonce to file
        try (FileOutputStream fos = new FileOutputStream("nonce.txt")) {
            fos.write(nonce);
        }

    

        String jsonString_with_sign_fresh = jsonObject.toString();
        byte[] documentBytes_with_sign_fresh = jsonString_with_sign_fresh.getBytes();



        //Get Secret Key

        Key secretKey = readSecretKey(args[2]);

        // Encrypt the document
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(documentBytes_with_sign_fresh);

        // Write the encrypted document to a file
        Files.write(Paths.get("encryptedDocument.json"), encryptedBytes);


        
    }

    private static byte[] readFile(String path) throws FileNotFoundException, IOException {
        FileInputStream fis = new FileInputStream(path);
        byte[] content = new byte[fis.available()];
        fis.read(content);
        fis.close();
        return content;
    }




    public static PrivateKey readPrivateKey(String privateKeyPath) throws Exception {
        byte[] privEncoded = readFile(privateKeyPath);
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privEncoded);
        KeyFactory keyFacPriv = KeyFactory.getInstance("RSA");
        PrivateKey priv = keyFacPriv.generatePrivate(privSpec);
        return priv;
    }

    public static Key readSecretKey(String secretKeyPath) throws Exception {
        byte[] encoded = readFile(secretKeyPath);
        SecretKeySpec keySpec = new SecretKeySpec(encoded, "AES");
        return keySpec;
    }
}
