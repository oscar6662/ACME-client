package services;

import fi.iki.elonen.NanoHTTPD;

import java.io.IOException;

public class CertificateHTTPSServer extends NanoHTTPD implements Runnable{

    public CertificateHTTPSServer(int port) {
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
}
