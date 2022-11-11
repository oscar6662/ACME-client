package services.http;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import utils.KeyStuff;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;

public class CertificateHTTPSServer implements Runnable {
    private KeyStuff ks;
    private List<Certificate> certificates;
    private HttpsServer httpsServer;
    public CertificateHTTPSServer(KeyStuff ks, List<Certificate> certificates) {
        this.ks = ks;
        this.certificates = certificates;
    }
    public void something() throws IOException, NoSuchAlgorithmException, CertificateException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
        InetSocketAddress Inet_Address = new InetSocketAddress(5001);
        httpsServer = HttpsServer.create(Inet_Address, 0);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        char[] password = "password".toCharArray();
        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
        store.load(null, password);
        store.setKeyEntry("main", ks.getPair().getPrivate(), password, certificates.toArray(new Certificate[]{}));
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(store, password);
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(store);
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
        httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            public void configure(HttpsParameters params) {
                try {
                    SSLContext sslContext1 = getSSLContext();
                    SSLEngine SSL_Engine = sslContext1.createSSLEngine();
                    params.setNeedClientAuth(false);
                    params.setCipherSuites(SSL_Engine.getEnabledCipherSuites());
                    params.setProtocols(SSL_Engine.getEnabledProtocols());
                    SSLParameters sslParameters = sslContext1.getSupportedSSLParameters();
                    params.setSSLParameters(sslParameters);
                } catch (Exception ex) {
                    System.out.println("Failed to create the HTTPS port");
                }
            }
        });
        httpsServer.setExecutor(null);
        httpsServer.start();
    }
    public void stop() {
        httpsServer.stop(0);
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

