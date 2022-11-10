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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static utils.Utils.sha256hash;

public class ChallengeHttpServer extends NanoHTTPD implements Runnable {
    private Map<String, String> map = new HashMap<>();
    public ChallengeHttpServer(int port) {
        super(port);
    }

    public void setTextChallenge(String a, String b) {
        this.map.put(a, b);
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
        if (!map.get(session.getUri()).isBlank()) {
            Response r = newFixedLengthResponse(map.get(session.getUri()));
            r.addHeader("Content-Type", "application/octet-stream");
            return r;
        }else {
            return newFixedLengthResponse(Response.Status.NOT_FOUND, "not found", "");
        }
    }
}
