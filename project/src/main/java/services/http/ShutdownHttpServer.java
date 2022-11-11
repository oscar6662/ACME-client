package services.http;

import fi.iki.elonen.NanoHTTPD;
import services.requestSender;

import java.io.IOException;

public class ShutdownHttpServer extends NanoHTTPD implements Runnable {
    private requestSender rs;
        private CertificateHTTPSServer cs;
    public ShutdownHttpServer(int port, requestSender rs, CertificateHTTPSServer cs) {
        super(port);
        this.rs = rs;
        this.cs = cs;
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
            rs.dc.shutTheServerDown();
            rs.httpc.shutTheServerDown();
            cs.stop();
           System.exit(0);
        }
        return newFixedLengthResponse("ACME Client Shutdown");
    }
}
