import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.X509Certificate;
import javax.json.*;
import javax.net.ssl.*;

import joseObjects.Nonce;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import services.AcmeFunctions;
import services.DnsServer;

public class main {
    private static String GET_URL = "https://localhost:14000/dir";
    private static String NEW_ORDER_URL;
    private static String NEW_ACCOUNT_URL;

    private static Nonce nonce;
    static DnsServer server;


    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeyException, SignatureException, OperatorCreationException {
        initialization();
        acmeInit();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String line = "";
        AcmeFunctions af = new AcmeFunctions(nonce, NEW_ACCOUNT_URL, NEW_ORDER_URL);
        while (line.equalsIgnoreCase("quit") == false) {
            line = in.readLine();
            switch (line) {
                case "dir":
                    af.newAccount();
                    break;
                case "newOrder":
                    af.newOrder();
                    break;
                case "finalizeOrder":
                    af.finalizeOrder();
                    break;
                case "newAuthz":
                    af.newAuthz();
                    break;
                case "dns01":
                    af.dns01();
                    break;
                default:
                    System.out.println("command not found, please try again or use \"help\"");
            }
        }
        in.close();
    }

    public static void initialization() throws NoSuchAlgorithmException, UnknownHostException, SocketException {
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
    }

    public static void acmeInit() throws IOException {
        URL url = new URL(GET_URL);
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
}
