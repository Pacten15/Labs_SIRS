package pt.tecnico;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.nio.file.*;

public class SecureReader {
    public static void main(String[] args) throws Exception {

        long MAX_AGE = 1000 * 6; // 1 day

        // Check arguments
        if (args.length < 1) {
            System.err.println("Argument(s) missing!");
            System.err.printf("Usage: java %s file%n", SecureReader.class.getName());
            return;
        }
        final String filename = args[0];

        // Load the public key
        PublicKey publicKey = readPublicKey(args[1]);

        // Read JSON object from file, and print its contets
        try (FileReader fileReader = new FileReader(filename)) {
            Gson gson = new Gson();
            JsonObject rootJson = gson.fromJson(fileReader, JsonObject.class);
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
            String jsonString = rootJson.toString();
            byte[] documentBytes = jsonString.getBytes();

            // Verify the digital signature
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(documentBytes);
            boolean isVerified = signature.verify(signatureBytes);

            if (isVerified) {
                System.out.println("The document is verified.");
            } else {
                System.out.println("The document is not verified.");
            }
            long currentTime = System.currentTimeMillis();
            if (currentTime - timestamp > MAX_AGE) {
                System.out.println("The document is not fresh.");
            } else {
                System.out.println("The document is fresh.");
}

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
}
