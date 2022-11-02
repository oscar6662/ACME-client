package joseObjects.jws;

import joseObjects.Jwk;

public class Protected {
    public String alg;
    public Jwk jwk;
    public String kid;
    public String nonce;
    public String url;
    public Protected(String alg, Jwk jwk, String nonce, String url) {
        this.alg = alg;
        this.jwk = jwk;
        this.nonce = nonce;
        this.url = url;
    }
    public Protected(String alg, String kid, String nonce, String url) {
        this.alg = alg;
        this.kid = kid;
        this.nonce = nonce;
        this.url = url;
    }
}
