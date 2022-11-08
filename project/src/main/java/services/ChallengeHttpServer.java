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
        System.out.println("response:");
        Response r = newFixedLengthResponse(textChallenge);
        System.out.println(r);
        r.addHeader("Content-Type", "application/octet-stream");
        return r;
    }
}
