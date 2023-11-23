package pt.tecnico;

import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.nio.file.*;


import com.google.gson.*;

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
}
