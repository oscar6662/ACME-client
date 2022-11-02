import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.net.URL;

public class Nonce {
    private String nonce;
    public Nonce(String getNonceUrl) throws IOException {

        URL url = new URL(getNonceUrl);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setRequestMethod("HEAD");
        nonce = connection.getHeaderField("Replay-Nonce");
    }

    public String getNonce() {
        return nonce;
    }
}
