import com.google.gson.Gson;
import com.google.gson.JsonObject;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.WalletUtils;
import org.web3j.utils.Numeric;

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


public class Main {

    private static String code;
    private static String did;
    private static String privateKey;
    private static String authServerEndpoint;

    private static String sendHttp(String endpoint, String body) throws IOException {
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
                String responseLine = null;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
            } catch (IOException ex) {
                ex.printStackTrace();
            }
            e.printStackTrace();
        } finally {
            return response.toString();
        }
    }

    private static void sendDid(){
        try {
            String response = sendHttp(authServerEndpoint + "/sendDid", "{\"did\": \"" + did + "\"}");
            Gson gson = new Gson();
            JsonObject jsonResponse = gson.fromJson(response, JsonObject.class);
            code = jsonResponse.get("code").getAsString();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String sendProof(){
        String jwt = "";
        try {
            String signedCode = EthereumMessageSigner.signMessage(code, privateKey);
            String body = "{\"did\": \"" + did +"\", \"signedCode\": \"" + signedCode + "\" }";
            String response = sendHttp(authServerEndpoint + "/sendProof", body);

            Gson gson = new Gson();
            JsonObject jsonResponse = gson.fromJson(response, JsonObject.class);
            jwt = jsonResponse.get("jwtToken").getAsString();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            return jwt;
        }
    }

    private static PublicKey retrieveAuthServerPublicKey(String authServerEndpoint) throws Exception {
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

        Gson gson = new Gson();
        JsonObject json = gson.fromJson(response.toString(), JsonObject.class);

        byte[] encodedPublic = Base64.getDecoder().decode(json.get("publicKey").getAsString());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublic);
        return keyFactory.generatePublic(publicKeySpec);
    }

    private static void checkClaims(String authserverPublicKeyEndpoint, String jwt) throws Exception {
        PublicKey pk = retrieveAuthServerPublicKey(authserverPublicKeyEndpoint);
        Jws<Claims> claims = null;
        try {
            claims = Jwts.parser()
                .setSigningKey(pk)
                .parseClaimsJws(jwt);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println(
            "Header: " + claims.getHeader().toString() +
            "\nIssuer: " + claims.getBody().getIssuer() +
            "\nBody: " + claims.getBody().toString()
        );
    }

    private static void loadPrivateKey(Properties properties) throws Exception {
        // Check if the wallet is already created and eventually, create a new one
        File myWallet = new File(properties.getProperty("wallet.path"));
        if (!myWallet.exists()) {
            System.out.println("Insert the private key (base64 encoded): ");
            Scanner in = new Scanner(System.in);
            Credentials credentials = Credentials.create(in.nextLine());
            ECKeyPair ecKeyPair = credentials.getEcKeyPair();
            String walletFileName = WalletUtils.generateWalletFile(properties.getProperty("wallet.password"), ecKeyPair, new File("./src/main/resources/"), true);

            properties.setProperty("wallet.path", "./src/main/resources/" + walletFileName);
            properties.store(new FileWriter("./src/main/resources/application.properties"), "Properties updated");
        }

        // Load credentials from the wallet
        Credentials credentials = WalletUtils.loadCredentials(properties.getProperty("wallet.password"), properties.getProperty("wallet.path"));
        byte[] bytes = credentials.getEcKeyPair().getPrivateKey().toByteArray();
        privateKey = Numeric.toHexString(bytes);
    }

    public static void main(String[] args) throws Exception {
        final Properties properties = new Properties();
        properties.load(new FileInputStream("./src/main/resources/application.properties"));
        did = properties.getProperty("did");
        loadPrivateKey(properties);
        authServerEndpoint = properties.getProperty("authServerEndpoint");

        sendDid();

        String jwt = sendProof();
        System.out.println(
            "JWT:\n" +
             jwt +
            "\n"
        );

        //checkClaims(authserverEndpoint + "/getPublicKey", jwt);
    }


}
