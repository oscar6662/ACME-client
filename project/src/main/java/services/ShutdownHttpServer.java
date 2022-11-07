package services;

import fi.iki.elonen.NanoHTTPD;

import java.io.IOException;

public class ShutdownHttpServer extends NanoHTTPD implements Runnable {
    public ShutdownHttpServer(int port) {
        super(port);
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
        if ("/shutdown".equals(session.getUri())) {
           System.exit(0);
        }
        return newFixedLengthResponse("ACME Client Shutdown");
    }
}
