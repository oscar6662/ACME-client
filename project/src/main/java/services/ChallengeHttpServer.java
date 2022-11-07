package services;

import fi.iki.elonen.NanoHTTPD;
import joseObjects.KeyStuff;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import static utils.Utils.sha256hash;

public class ChallengeHttpServer extends NanoHTTPD implements Runnable {
    private String textChallenge;
    public ChallengeHttpServer(int port) {
        super(port);
    }

    public void setTextChallenge(String textChallenge) {
        this.textChallenge = textChallenge;
    }

    @Override
    public void run() {
        try {
            this.start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    @Override
    public Response serve(IHTTPSession session) {
        Response r = newFixedLengthResponse(textChallenge);
        r.addHeader("Content-Type", "application/octet-stream");
        return r;
    }
    public void startHttpChallenge(KeyStuff ks, ChallengeHttpServer c) throws NoSuchAlgorithmException, IOException {
        PublicKey pk = ks.getPair().getPublic();
        String toEncode = ks.getHttp01().getToken()+"."+ Base64.encodeBase64URLSafeString(thumbprint(pk));
        c.setTextChallenge(Base64.encodeBase64URLSafeString(sha256hash(toEncode)));
        c.start();
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
