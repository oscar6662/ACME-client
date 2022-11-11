package services.Http;

import services.Http.ChallengeHttpServer;
import utils.KeyStuff;
import org.apache.commons.codec.binary.Base64;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import static utils.Utils.thumbprint;

public class Http01Challenge {
    private ChallengeHttpServer server;

    public Http01Challenge() throws IOException {
        server = new ChallengeHttpServer(5002);
        server.start();
    }

    public void startHttpChallenge(KeyStuff ks, String domain) throws NoSuchAlgorithmException, IOException {
        PublicKey pk = ks.getPair().getPublic();
        int i = ks.getIndexforhttp(domain);
        String toEncode = ks.getHttp01().get(i).getToken()+"."+Base64.encodeBase64URLSafeString(thumbprint(pk));
        server.setTextChallenge("/.well-known/acme-challenge/"+ks.getHttp01().get(i).getToken(), toEncode);
    }
    public void shutTheServerDown(){
        server.stop();
    }

}
