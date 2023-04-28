package dto;

public class Proof {

    private String did;
    private String signedCode;

    public Proof() { }

    public Proof(String did, String signedCode) {
        this.did = did;
        this.signedCode = signedCode;
    }

    public String getDid() {
        return did;
    }

    public void setDid(String did) {
        this.did = did;
    }

    public String getSignedCode() {
        return signedCode;
    }

    public void setSignedCode(String signedCode) {
        this.signedCode = signedCode;
    }
}
