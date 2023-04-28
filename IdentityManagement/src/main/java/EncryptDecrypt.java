import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class EncryptDecrypt {

    public static final String algorithm = "RSA/ECB/PKCS1Padding";
    private final KeyPair keyPair;

    public EncryptDecrypt(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public String encryptProperty(String property) {
        String result = "";
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

            byte[] input = property.getBytes();
            cipher.update(input);

            byte[] cipherText = cipher.doFinal();
            result = Base64.getEncoder().encodeToString(cipherText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public String decryptProperty(String cipherText) {
        String result = "";
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] decipheredText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
            result = new String(decipheredText, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public static String encryptProperty(String property, PublicKey publicKey) {
        String result = "";
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] input = property.getBytes();
            cipher.update(input);

            byte[] cipherText = cipher.doFinal();
            result = Base64.getEncoder().encodeToString(cipherText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public static String decryptProperty(String cipherText, PrivateKey privateKey) {
        String result = "";
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decipheredText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
            result = new String(decipheredText, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

}
