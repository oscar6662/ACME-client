package joseObjects;

public class Jwk {
    public String kty;
    public String crv;
    public String x;
    public String y;
    public Jwk(String kty, String crv, String x, String y) {
        this.kty = kty;
        this.crv = crv;
        this.x = x;
        this.y = y;
    }
}
