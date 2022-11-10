import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.List;
import javax.json.*;
import javax.net.ssl.*;

import joseObjects.Nonce;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import services.AcmeFunctions;
import services.ArgumentParser;
import services.ShutdownHttpServer;

public class main {
    // different certificate be used depending on machine it's running
    //private static final boolean DEV = System.getenv().getOrDefault("DEV", "false").equals("true");
    private static final boolean DEV = false;
    private static String NEW_ORDER_URL;
    private static String NEW_ACCOUNT_URL;
    private static Nonce nonce;
    private static ArgumentParser ap;
    private static AcmeFunctions af;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeyException, SignatureException, OperatorCreationException, InterruptedException, UnrecoverableKeyException, CertificateException, KeyStoreException, KeyManagementException {
        initialization();
        ap = new ArgumentParser(args);
        acmeInit(ap.ACMEServerDirectory);
        af = new AcmeFunctions(nonce, NEW_ACCOUNT_URL, NEW_ORDER_URL, ap.DNSServerAddress, ap.challengeType);
        getTheCertificate(ap, af);
    }

    /**
     * Sets Certificate for Https connections
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws KeyStoreException
     * @throws KeyManagementException
     * @throws CertificateException
     */
    private static void initialization() throws NoSuchAlgorithmException, IOException, KeyStoreException, KeyManagementException, CertificateException {
        if (DEV) {
            List<String> strings;
            strings = Files.readAllLines(Path.of("/Users/oscar6662/Documents/Skóli/eth-22/networkSecurity/pebble/test/certs/pebble.minica.pem"));
            strings.remove(0);
            strings.remove(strings.size() - 1);
            String certificateString =  String.join("", strings);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Certificate certificate;
            try (ByteArrayInputStream certificateStream = new ByteArrayInputStream(Base64.getDecoder().decode(certificateString))) {
                certificate = certificateFactory.generateCertificate(certificateStream);
            }
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] password = "password".toCharArray();
            store.load(null, password);
            store.setCertificateEntry("pebble", certificate);
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(store);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagers, null);
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
        } else {
            List<String> strings;
            strings = Files.readAllLines(Path.of("pebble.minica.pem"));
            strings.remove(0);
            strings.remove(strings.size() - 1);
            String certificateString =  String.join("", strings);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Certificate certificate;
            try (ByteArrayInputStream certificateStream = new ByteArrayInputStream(Base64.getDecoder().decode(certificateString))) {
                certificate = certificateFactory.generateCertificate(certificateStream);
            }
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] password = "password".toCharArray();
            store.load(null, password);
            store.setCertificateEntry("pebble", certificate);
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(store);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagers, null);
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
        }
    }

    /**
     *
     * @param getUrl Url to be used to get different acme url's
     * @throws IOException
     */
    private static void acmeInit(String getUrl) throws IOException {
        URL url = new URL(getUrl);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        if (connection != null) {
            try {
                BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                }
                br.close();
                JsonReader jsonReader = Json.createReader(new StringReader(sb.toString()));
                JsonObject jObj = jsonReader.readObject();
                nonce = new Nonce(jObj.getString("newNonce"));
                NEW_ORDER_URL =  jObj.getString("newOrder");
                NEW_ACCOUNT_URL =  jObj.getString("newAccount");
            } catch (IOException ioException) {
                ioException.printStackTrace();
            }
        }
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    private static void getTheCertificate(ArgumentParser ap, AcmeFunctions af) throws IOException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, OperatorCreationException, InterruptedException, UnrecoverableKeyException, CertificateException, KeyStoreException {
        af.newAccount();
        af.newOrder(ap.domainList);
        af.newAuthz();

        if (ap.challengeType.equals("dns01")) af.dns01();
        else if (ap.challengeType.equals("http01")) af.http01();

        int counter = 0;
        while (!af.getKs().isReady() && counter <10) {
            Thread.sleep(1000);
            af.checkStatus();
            counter++;
        }
        af.finalizeOrder(ap.domainList);
        counter = 0;
        while (!af.getKs().isAuthStatus() && counter <10) {
            Thread.sleep(1000);
            af.checkStatus();
            counter++;
        }
        af.downloadCertificate();
        af.createServer(ap.shouldRevoke);
    }
}
