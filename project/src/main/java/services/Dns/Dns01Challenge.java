package services.Dns;

import services.Dns.DnsServer;
import utils.KeyStuff;
import org.apache.commons.codec.binary.Base64;

import java.net.SocketException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import static utils.Utils.sha256hash;
import static utils.Utils.thumbprint;


public class Dns01Challenge {
    public DnsServer server;

    public Dns01Challenge(String DNSServerAddress) throws SocketException {
        server = new DnsServer(DNSServerAddress);
        server.start();
    }
    public void startDnsChallenge(KeyStuff ks, String domain, boolean wildcard) throws NoSuchAlgorithmException, SocketException {
        PublicKey pk = ks.getPair().getPublic();
        int i = ks.getIndexforDns(domain, wildcard);
        String toEncode = ks.getDns01().get(i).getToken()+"."+Base64.encodeBase64URLSafeString(thumbprint(pk));
        server.setTextChallenge("_acme-challenge."+ks.getDns01().get(i).getDomain()+".",Base64.encodeBase64URLSafeString(sha256hash(toEncode)));
    }
    public void shutTheServerDown() {
        server.stopServer();
    }
}
