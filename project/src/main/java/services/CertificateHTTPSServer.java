package services;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import fi.iki.elonen.NanoHTTPD;
import joseObjects.KeyStuff;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;
/*
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
        return newFixedLengthResponse("Sæææækluir");
    }

    @Override
    public void run() {
        try {
            this.start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}*/

public class CertificateHTTPSServer implements Runnable {
    private KeyStuff ks;
    private List<Certificate> certificates;
    public CertificateHTTPSServer(KeyStuff ks, List<Certificate> certificates) {
        this.ks = ks;
        this.certificates = certificates;
    }
    public void something() throws IOException, NoSuchAlgorithmException, CertificateException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
        InetSocketAddress Inet_Address = new InetSocketAddress(5001);

        //initialize the HTTPS server
        HttpsServer HTTPS_Server = HttpsServer.create(Inet_Address, 0);
        SSLContext SSL_Context = SSLContext.getInstance("TLS");

        // initialise the keystore
        char[] password = "password".toCharArray();
        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
        store.load(null, password);
        store.setKeyEntry("main", ks.getPair().getPrivate(), password, certificates.toArray(new Certificate[]{}));

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(store, password);

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(store);

        // setup the HTTPS context and parameters
        SSL_Context.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
        HTTPS_Server.setHttpsConfigurator(new HttpsConfigurator(SSL_Context) {
            public void configure(HttpsParameters params) {
                try {
                    // initialise the SSL context
                    SSLContext SSL_Context = getSSLContext();
                    SSLEngine SSL_Engine = SSL_Context.createSSLEngine();
                    params.setNeedClientAuth(false);
                    params.setCipherSuites(SSL_Engine.getEnabledCipherSuites());
                    params.setProtocols(SSL_Engine.getEnabledProtocols());

                    // Set the SSL parameters
                    SSLParameters SSL_Parameters = SSL_Context.getSupportedSSLParameters();
                    params.setSSLParameters(SSL_Parameters);
                    System.out.println("The HTTPS server is connected");

                } catch (Exception ex) {
                    System.out.println("Failed to create the HTTPS port");
                }
            }
        });
        HTTPS_Server.setExecutor(null); // creates a default executor
        HTTPS_Server.start();
    }

    @Override
    public void run() {
        try {
            this.something();
        } catch (IOException | UnrecoverableKeyException | CertificateException | NoSuchAlgorithmException |
                 KeyStoreException | KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }
}

