package microservice;

import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;

public class EthereumMessageSigner {

    // Sign a message (ECDSA) with an encoded base64 private key.
    public static String signMessage(String message, String privateKey){
        Credentials credentials = Credentials.create(privateKey);

        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        Sign.SignatureData signatureData = Sign.signMessage(messageBytes, credentials.getEcKeyPair());

        byte[] retval = new byte[65];
        System.arraycopy(signatureData.getR(), 0, retval, 0, 32);
        System.arraycopy(signatureData.getS(), 0, retval, 32, 32);
        System.arraycopy(signatureData.getV(), 0, retval, 64, 1);

        return Numeric.toHexString(retval);
    }

    // Extract and verify if the address that signed the message is equal to ethereumAddress argument.
    public static boolean verifyMessageSignature(String message, String signature, String ethereumAddress) throws SignatureException {
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        byte[] bytes = Numeric.hexStringToByteArray(signature);
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        byte v = bytes[64];

        System.arraycopy(bytes, 0, r, 0, 32);
        System.arraycopy(bytes, 32, s, 0, 32);

        Sign.SignatureData signatureData = new Sign.SignatureData(v, r, s);
        BigInteger pK = Sign.signedMessageToKey(messageBytes, signatureData);

        return Keys.getAddress(pK).equals(ethereumAddress.substring(2));
    }
}
