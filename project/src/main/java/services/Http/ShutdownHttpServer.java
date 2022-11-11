package services.Http;

import fi.iki.elonen.NanoHTTPD;
import services.RequestSender;

import java.io.IOException;

public class ShutdownHttpServer extends NanoHTTPD implements Runnable {
    private RequestSender rs;
    private CertificateHttpsServer cs;
    public ShutdownHttpServer(int port, RequestSender rs, CertificateHttpsServer cs) {
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
