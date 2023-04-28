package dto;

public class PublicKeyDTO {

    private String publicKey;

    public PublicKeyDTO() { }

    public PublicKeyDTO(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
}
