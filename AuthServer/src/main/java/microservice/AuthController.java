package microservice;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import dto.*;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@CrossOrigin
public class AuthController {

    static HashMap<String, Map<String, String>> activePool = new HashMap<>();

    private JwtTokenUtil jwtTokenUtil;
    private EncryptDecrypt encryptDecrypt;
    private KeyPair keyPair;
    private String jksPath;
    private String alias;
    private String password;
    private String fireflyEndpoint;
    private String revokedDidsEndpoint;

    @Autowired
    public void setJksPath(@Value("${jks.path}") String jksPath) {
        this.jksPath = jksPath;
    }

    @Autowired
    public void setAlias(@Value("${jks.alias}") String alias) {
        this.alias = alias;
    }

    @Autowired
    public void setPassword(@Value("${jks.password}") String password) {
        this.password = password;
    }

    @Autowired public void setFireflyEndpoint(@Value("${web3.gateway}") String fireflyEndpoint) {
        this.fireflyEndpoint = fireflyEndpoint;
    }

    @Autowired public void setRevokedDidsEndpoint(@Value("${revokedDidsEndpoint}") String revokedDidsEndpoint) {
        this.revokedDidsEndpoint = revokedDidsEndpoint;
    }

    @PostConstruct
    private void init() throws Exception {
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        char[] pwdArray = password.toCharArray();

        InputStream in = this.getClass().getResourceAsStream(jksPath);
        keystore.load(in, pwdArray);
        in.close();

        final PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, pwdArray);
        final Certificate cert = keystore.getCertificate(alias);
        final PublicKey publicKey = cert.getPublicKey();
        this.keyPair = new KeyPair(publicKey, privateKey);
        this.jwtTokenUtil = new JwtTokenUtil(keyPair.getPrivate());
        this.encryptDecrypt = new EncryptDecrypt(keyPair);
    }

    // This endpoint have been used to retrieve the encoded base64 public key for encryption of DID document's properties.
    @RequestMapping(value = "/getPublicKey", method = RequestMethod.GET, produces = "application/json")
    @ResponseBody
    public ResponseEntity<?> getPublicKey() throws Exception {
        return ResponseEntity.ok(
            new PublicKeyDTO(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()))
        );
    }

    // This endpoint have been used for the first step of the cryptographic game.
    @RequestMapping(value = "/sendDid", method = RequestMethod.POST, produces="application/json")
    @ResponseBody
    public ResponseEntity<?> createProof(@RequestBody Did authenticationRequest) throws Exception {

        SecureRandom rand = new SecureRandom();
        String code = String.valueOf(rand.nextInt(100000, 1000000));

        Map<String, String> map = new HashMap<>();
        map.put("code", code);
        map.put("status", "code_send");

        activePool.put(
                authenticationRequest.getDid(),
                map
        );
        return ResponseEntity.ok(new RandomCode(code));
    }

    // This endpoint have been used for the second step of the cryptographic game.
    @RequestMapping(value = "/sendProof", method = RequestMethod.POST, produces="application/json")
    @ResponseBody
    public ResponseEntity<?> createJwt(@RequestBody Proof proofRequest) throws Exception {
        Map<String, String> map = activePool.get(proofRequest.getDid());

        String code = map.get("code");

        boolean codeVerified = EthereumMessageSigner.verifyMessageSignature(
            code,
            proofRequest.getSignedCode(),
            retrieveAddressFromDid(proofRequest.getDid())
        );

        if (!codeVerified) {
            map.put("status", "unverified");
            activePool.put(
                proofRequest.getDid(),
                map
            );
            return new ResponseEntity<>(
                new JwtResponse("The signature doesn't match with the owner of the DID!"),
                HttpStatus.UNAUTHORIZED
            );
        }

        if (isRevoked(proofRequest.getDid())) {
            return new ResponseEntity<>(
                new JwtResponse("This DID is revoked!"),
                HttpStatus.UNAUTHORIZED
            );
        }

        map.put("status", "codeVerified");
        activePool.put(
            proofRequest.getDid(),
            map
        );
        Map<String, Object> claims = retrieveInfoFromDid(proofRequest.getDid());
        String token = jwtTokenUtil.generateToken(
            claims,
            proofRequest.getDid().split(":")[2]
        );
        return ResponseEntity.ok(new JwtResponse(token));
    }

    // Check if the DID argument is revoked or not using the deployed smart contract.
    private boolean isRevoked(String did) {
        boolean isRevoked = false;
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(revokedDidsEndpoint))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{ \"input\": { \"did\": \"" + did.split(":")[2] + "\" } }"))
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            Gson gson = new Gson();
            JsonObject isRevokedResponse = gson.fromJson(response.body(), JsonObject.class);
            isRevoked = isRevokedResponse.get("output").getAsBoolean();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            return isRevoked;
        }
    }

    // Retrieve and decrypt the DID document's properties.
    private Map<String, Object> retrieveInfoFromDid(String did){
        Map<String, Object> didInfo = new HashMap<>();
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder(URI.create(fireflyEndpoint + "/api/v1/identities/" + did)).build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            Gson gson = new Gson();
            JsonObject didDoc = gson.fromJson(response.body(), JsonObject.class);
            didDoc.get("profile").getAsJsonObject().asMap().forEach(
                    (key, value) -> didInfo.put(key, encryptDecrypt.decryptProperty(value.getAsString()))
            );
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            return didInfo;
        }
    }

    // Retrieve the ethereum address of the DID argument.
    private String retrieveAddressFromDid(String did){
        String address = "";
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder(URI.create(fireflyEndpoint + "/api/v1/network/diddocs/" + did)).build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            Gson gson = new Gson();
            JsonObject didDoc = gson.fromJson(response.body(), JsonObject.class);
            address = didDoc.getAsJsonArray("verificationMethod").get(0).getAsJsonObject().get("blockchainAcountId").getAsString();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            return address;
        }
    }

}
