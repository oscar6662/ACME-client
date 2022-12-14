package services.dns;

import utils.KeyStuff;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import static utils.Utils.sha256hash;


public class Dns01Challenge {
    public DnsServer server;

    public Dns01Challenge(String DNSServerAddress) throws SocketException {
        server = new DnsServer(10053, DNSServerAddress);
        server.start();
    }
    public void startDnsChallenge(KeyStuff ks, String domain, boolean wildcard) throws NoSuchAlgorithmException, SocketException {
        System.out.println("here"+domain+ " "+wildcard);
        PublicKey pk = ks.getPair().getPublic();
        int i = ks.getIndexforDns(domain, wildcard);
        String toEncode = ks.getDns01().get(i).getToken()+"."+Base64.encodeBase64URLSafeString(thumbprint(pk));
        if (wildcard){
            server.setTextChallenge("_acme-challenge."+ks.getDns01().get(i).getDomain()+".",Base64.encodeBase64URLSafeString(sha256hash(toEncode)));
        } else
            server.setTextChallenge("_acme-challenge."+ks.getDns01().get(i).getDomain()+".",Base64.encodeBase64URLSafeString(sha256hash(toEncode)));
    }
    public void shutTheServerDown() {
        server.stopServer();
    }
    public byte[] thumbprint(PublicKey pk) throws NoSuchAlgorithmException {
        String template = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}";
        String x = Base64.encodeBase64URLSafeString(((ECPublicKey) pk).getQ().getAffineXCoord().getEncoded());
        String y = Base64.encodeBase64URLSafeString(((ECPublicKey) pk).getQ().getAffineYCoord().getEncoded());
        String s =  String.format(template, x, y);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(s.getBytes(StandardCharsets.UTF_8));
        return md.digest();
    }
}
