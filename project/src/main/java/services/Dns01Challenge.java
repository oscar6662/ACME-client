package services;

import joseObjects.KeyStuff;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import static utils.Utils.sha256hash;


public class Dns01Challenge {
    public DnsServer server;

    public Dns01Challenge(String DNSServerAddress) throws SocketException {
        server = new DnsServer(10053, DNSServerAddress);
        server.start();
    }
    public void startDnsChallenge(KeyStuff ks, String domain) throws NoSuchAlgorithmException, SocketException {
        PublicKey pk = ks.getPair().getPublic();
        int i = ks.getIndexforDns(domain);
        String toEncode = ks.getDns01().get(i).getToken()+"."+Base64.encodeBase64URLSafeString(thumbprint(pk));
        server.setTextChallenge("_acme-challenge."+ks.getDns01().get(i).getDomain()+".",Base64.encodeBase64URLSafeString(sha256hash(toEncode)));

    }
    public void shutTheServerDown() {
        server.stopServer();
    }
    public byte[] thumbprint(PublicKey pk) throws NoSuchAlgorithmException {
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
