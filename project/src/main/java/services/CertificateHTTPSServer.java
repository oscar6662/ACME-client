package services;

import fi.iki.elonen.NanoHTTPD;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

public class CertificateHTTPSServer extends NanoHTTPD implements Runnable{

    public CertificateHTTPSServer(int port) {
        super(port);
    }
    @Override
    protected ClientHandler createClientHandler(Socket finalAccept, InputStream inputStream) {
        return super.createClientHandler(finalAccept, inputStream);
    }

    @Override
    public Response serve(IHTTPSession session) {
        return newFixedLengthResponse("Sæææælir");
    }

    @Override
    public void run() {
        try {
            this.start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
