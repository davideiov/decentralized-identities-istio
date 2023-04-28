import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Properties;
import java.util.Scanner;

public class IdentityManagement {

    private static String[] props;
    private static String fireflyEndpoint;
    private static String revokationEndpoint;
    private static String parent;
    private static PublicKey publicKey;

    private static void loadProperties() throws Exception {
        final Properties properties = new Properties();
        properties.load(new FileInputStream("./src/main/resources/application.properties"));
        props = properties.getProperty("requiredProperties").split(",");
        fireflyEndpoint = properties.getProperty("web3.gateway");
        revokationEndpoint = properties.getProperty("revokationEndpoint");
        parent = properties.getProperty("web3.organizationId");
        publicKey = retrievePublicKey(properties.getProperty("authserverPublicKeyEndpoint"));
    }

    private static PublicKey retrievePublicKey(String authServerEndpoint) throws Exception {
        URL url = new URL (authServerEndpoint);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestProperty("Accept", "application/json");

        BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
        String inputLine;
        StringBuilder response = new StringBuilder();

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        JSONParser parser = new JSONParser();
        JSONObject json = (JSONObject) parser.parse(response.toString());

        byte[] encodedPublic = Base64.getDecoder().decode(json.get("publicKey").toString());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublic);
        return keyFactory.generatePublic(publicKeySpec);
    }

    private static String sendHttp(String endpoint, String body) throws Exception{
        StringBuilder response = new StringBuilder();
        URL url = new URL (endpoint);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        try {
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/json");
            con.setRequestProperty("Accept", "application/json");
            con.setDoOutput(true);

            try(OutputStream os = con.getOutputStream()) {
                byte[] input = body.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            try(BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream(), StandardCharsets.UTF_8))) {
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
            }
        } catch (Exception e) {
            try(BufferedReader br = new BufferedReader(new InputStreamReader(con.getErrorStream(), StandardCharsets.UTF_8))) {
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
            } catch (IOException ex) {
                ex.printStackTrace();
            }
            e.printStackTrace();
        }
        return response.toString();
    }

    private static String insertIdentity(String ethAddr, String name, String[] identityProps) throws Exception {
        StringBuilder profile = new StringBuilder();
        for(int i = 0; i < props.length; i++) {
            profile.append(String.format("\"%s\": \"%s\"", props[i], EncryptDecrypt.encryptProperty(identityProps[i], publicKey)));
            if (i != props.length - 1)
                profile.append(",");
        }

        String body = String.format(
            "{\"description\": \"%s\", " +
            "\"key\": \"%s\"," +
            "\"name\": \"%s\"," +
            "\"parent\": \"%s\"," +
            "\"profile\": {%s}}",
            "demo identity", ethAddr, name, parent, profile
        );

        return sendHttp(fireflyEndpoint + "/api/v1/identities", body);
    }

    private static void createIdentity(Scanner in) throws Exception {
        System.out.println("Insert the ethereum address of the user>>>");
        String ethAddr = in.nextLine();

        System.out.println("Insert the name of the identity (including alphanumerics (a-zA-Z0-9), dot (.), dash (-) and underscore (_))>>>");
        String name = in.nextLine();

        String[] identityProps = new String[props.length];
        System.out.println("--- Please insert the properties of the identity");
        for(int i=0; i < props.length; i++){
            if(props[i].equals("birth"))
                System.out.println("\nInsert " + props[i] + " property (dd/mm/yyyy) >>>");
            else
                System.out.println("\nInsert " + props[i] + " property >>>");

            identityProps[i] = in.nextLine();
        }

        System.out.println("Properties saved...\n");
        String response = insertIdentity(ethAddr, name, identityProps);
        System.out.println("Response:\n" + response + "\n");
    }

    private static void revokeIdentity(Scanner in) throws Exception {
        System.out.println("Insert the DID of the user>>>");
        String did = in.nextLine();

        String body = String.format(
            "{\"input\": {\"did\": \"%s\"} }",
            did
        );

        sendHttp(revokationEndpoint, body);

        System.out.println("The identity of " + did + " has been revoked succesfully.");
    }

    public static void main(String[] args) throws Exception {
        loadProperties();

        Scanner in = new Scanner(System.in);
        System.out.println("----- Welcome to identities management -----\n");
        System.out.println("Press 1 to issue a new identity or 2 to revoke an issued DID:");

        switch (Integer.parseInt(in.nextLine())) {
            case 1: createIdentity(in);
                break;
            case 2: revokeIdentity(in);
                break;
        }

        in.close();
    }
}
