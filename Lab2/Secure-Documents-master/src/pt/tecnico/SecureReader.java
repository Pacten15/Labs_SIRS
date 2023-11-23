package pt.tecnico;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public class SecureReader {
    public static void main(String[] args) throws Exception {

        long MAX_AGE = 1000*60*60*24; // 1 day

        // Check arguments
        if (args.length < 1) {
            System.err.println("Argument(s) missing!");
            System.err.printf("Usage: java %s file%n", SecureReader.class.getName());
            return;
        }
        final String filename = args[0];


        // Load the public key
        PublicKey publicKey = readPublicKey(args[1]);

        //Load nonce 
        byte[] nonce = readFile(args[2]);


        // Load the secret key
        Key secretKey = readSecretKey(args[3]);


        //Read encrypted file and get json
        // Read the file and store its contents in bytes
        byte[] encryptedBytes = Files.readAllBytes(Paths.get(filename));

         // Decrypt the document
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        // Convert the decrypted bytes to a JSON object
        String jsonString = new String(decryptedBytes);
        JsonObject rootJson = new Gson().fromJson(jsonString, JsonObject.class);
        System.out.println("JSON object: " + rootJson);
        JsonObject headerObject = rootJson.get("header").getAsJsonObject();
        System.out.println("Document header:");
        System.out.println("Author: " + headerObject.get("author").getAsString());
        System.out.println("Version: " + headerObject.get("version").getAsInt());
        JsonArray tagsArray = headerObject.getAsJsonArray("tags");
        System.out.print("Tags: ");
        for (int i = 0; i < tagsArray.size(); i++) {
            System.out.print(tagsArray.get(i).getAsString());
            if (i < tagsArray.size() - 1) {
                System.out.print(", ");
            } else {
                System.out.println(); // Print a newline after the final tag
            }
        }
        System.out.println("Title: " + headerObject.get("title").getAsString());
        System.out.println("Document body: " + rootJson.get("body").getAsString());
        System.out.println("Document status: " + rootJson.get("status").getAsString());
        
         // Extract the signature from the JSON object
        String signatureString = rootJson.get("signature").getAsString();
        byte[] signatureBytes = Base64.getDecoder().decode(signatureString);
        // Extract the timestamp from the JSON object
        long timestamp = rootJson.get("timestamp").getAsLong();
        
        // Remove the signature from the JSON object
        rootJson.remove("signature");
        // Remove the timestamp from the JSON object
        rootJson.remove("timestamp");
        // Convert the JSON object to a byte array
        String jsonString_verified = rootJson.toString();
        byte[] documentBytes = jsonString_verified.getBytes();
        // Verify the digital signature
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(documentBytes);
        signature.update(nonce);
        boolean isVerified = signature.verify(signatureBytes);
        if (isVerified) {
            System.out.println("The document is verified.");
        } else {
            System.out.println("The document is not verified.");
        }
        long currentTime = System.currentTimeMillis();
        if (currentTime - timestamp > MAX_AGE) {
            System.out.println("The document sent in the right time frame.");
        } else {
            System.out.println("The document sent in the wrong time frame.");
        }
    }
    

    private static byte[] readFile(String path) throws FileNotFoundException, IOException {
        FileInputStream fis = new FileInputStream(path);
        byte[] content = new byte[fis.available()];
        fis.read(content);
        fis.close();
        return content;
    }

    public static PublicKey readPublicKey(String publicKeyPath) throws Exception {
        System.out.println("Reading public key from file " + publicKeyPath + " ...");
        byte[] pubEncoded = readFile(publicKeyPath);
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubEncoded);
        KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
        PublicKey pub = keyFacPub.generatePublic(pubSpec);
        return pub;
    }

    public static Key readSecretKey(String secretKeyPath) throws Exception {
        byte[] encoded = readFile(secretKeyPath);
        SecretKeySpec keySpec = new SecretKeySpec(encoded, "AES");
        return keySpec;
    }
}
