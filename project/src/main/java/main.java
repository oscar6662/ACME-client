import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import javax.net.ssl.*;
import org.json.*;

public class main {

    private static final  String GET_URL = "https://localhost:14000/dir";

    public static void main(String[] args) throws IOException, InterruptedException, NoSuchAlgorithmException {
        initialization();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String line = "";

        while (line.equalsIgnoreCase("quit") == false) {
            line = in.readLine();
            // System.out.println(line); // For debuging purposes only!
            switch(line) {
                case "dir":
                    sendGet();
                    break;
                case "something":
                    // else
                    break;
                default:
                    System.out.println("command not found, please try again or use \"help\"");
            }
        }
        in.close();
    }

    public static void initialization() throws NoSuchAlgorithmException{
        TrustManager[] trustAllCerts = new TrustManager[] {
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

    public static void sendGet() throws IOException, InterruptedException {
        URL url = new URL(GET_URL);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        if (connection != null) {
            try {
                System.out.println("Response code= " + connection.getResponseCode() + "\n");
                System.out.println("Printing url content\n");
                BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String input = br.readLine();
                System.out.println(input);
                JSONObject json = new JSONObject(new StringReader(input);
                System.out.println(json);
                br.close();
            } catch (IOException ioException) {
                ioException.printStackTrace();
            }
        }
    }
}
