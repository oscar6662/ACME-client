package services;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import joseObjects.Challenge;
import joseObjects.KeyStuff;
import joseObjects.Nonce;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

public class requestSender {
    Dns01Challenge dc = new Dns01Challenge();
    public void sendPost(String getUrl, String jws, Nonce nonce, KeyStuff ks, String motivation) throws IOException {
        URL url = new URL(getUrl);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/jose+json");
        connection.setRequestProperty("Accept-Charset", "utf-8");
        connection.setDoOutput(true);
        byte[] outputData = jws.getBytes(StandardCharsets.UTF_8);
        connection.setFixedLengthStreamingMode(outputData.length);
        connection.connect();
        try(OutputStream os = connection.getOutputStream()) {
            os.write(outputData);
        }

        if (connection != null) {
            try {
                nonce.setNonce(connection.getHeaderField("Replay-Nonce"));
                if (motivation.equals("newAccount")) ks.setLocation(connection.getHeaderField("Location"));

                BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                    System.out.println(line);
                }
                br.close();
                if (motivation.equals("newOrder")) {
                    JsonReader jsonReader = Json.createReader(new StringReader(sb.toString()));
                    JsonObject jObj = jsonReader.readObject();
                    ks.setFinalizeUrl(jObj.getString("finalize"));
                    ks.setAuthz(jObj.getJsonArray("authorizations").getString(0));
                }
                if (motivation.equals("newAuthz")) {
                    com.google.gson.JsonObject jObj = new JsonParser().parse(new StringReader(sb.toString())).getAsJsonObject();
                    Gson gson = new Gson();
                    JsonArray ja = jObj.getAsJsonArray("challenges");
                    for (int i = 0; i <ja.size(); i++) {
                        String challengeType = ja.get(i).getAsJsonObject().get("type").toString();
                        Challenge challenge = gson.fromJson(ja.get(i).toString(), Challenge.class);
                        switch (challengeType) {
                            case "\"http-01\"":
                                ks.setHttp01(challenge);
                                break;
                            case "\"tls-alpn-01\"":
                                ks.setTlsAlpn01(challenge);
                                break;
                            case "\"dns-01\"":
                                ks.setDns01(challenge);
                                dc.startDnsChallenge(ks);
                                break;
                            default:
                                System.out.println("shit challenge");
                    }}
                }
                // JsonReader jsonReader = Json.createReader(new StringReader(sb.toString()));
                // JsonObject jObj = jsonReader.readObject();

            } catch (IOException | NoSuchAlgorithmException ioException) {
                BufferedReader br = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                    System.out.println(line);
                }
                ioException.printStackTrace();
            }
        }
    }

}
