public class Protected {
    public String alg;
    public Jwk jwk;
    public String nonce;
    public String url;
    public Protected(String alg, Jwk jwk, String nonce, String url) {
        this.alg = alg;
        this.jwk = jwk;
        this.nonce = nonce;
        this.url = url;
    }
}
