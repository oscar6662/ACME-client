package services;

import joseObjects.KeyStuff;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import services.DnsServer;
import static utils.Utils.sha256hash;


public class Dns01Challenge {
    public static void startDnsChallenge(KeyStuff ks) throws NoSuchAlgorithmException, SocketException {
        PublicKey pk = ks.getPair().getPublic();
        String toEncode = ks.getDns01().getToken()+"."+Base64.encodeBase64URLSafeString(thumbprint(pk));
        DnsServer server = new DnsServer(10053);
        server.setTextChallenge(Base64.encodeBase64URLSafeString(sha256hash(toEncode)));
        server.start();
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
