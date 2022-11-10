package services;

import joseObjects.KeyStuff;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;


public class Http01Challenge {
    private ChallengeHttpServer server;

    public Http01Challenge() {
        server = new ChallengeHttpServer(5002);
    }

    public void startHttpChallenge(KeyStuff ks) throws NoSuchAlgorithmException, IOException {
        PublicKey pk = ks.getPair().getPublic();
        String toEncode = ks.getHttp01().getToken()+"."+Base64.encodeBase64URLSafeString(thumbprint(pk));
        server.setTextChallenge(toEncode);
        server.start();
    }
    public void shutTheServerDown(){
        server.stop();
    }
    public static byte[] thumbprint(PublicKey pk) throws NoSuchAlgorithmException {
        String template = "{\"crv\":\"%s\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}";
        Object crv = "P-256";
        Object x = Base64.encodeBase64URLSafeString(((ECPublicKey) pk).getQ().getAffineXCoord().getEncoded());
        Object y = Base64.encodeBase64URLSafeString(((ECPublicKey) pk).getQ().getAffineYCoord().getEncoded());
        String s =  String.format(template, crv, x, y);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(s.getBytes(StandardCharsets.UTF_8));
        return md.digest();
    }
}
