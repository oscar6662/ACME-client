package services.Http;

import fi.iki.elonen.NanoHTTPD;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class ChallengeHttpServer extends NanoHTTPD implements Runnable {
    private final Map<String, String> map = new HashMap<>();
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
