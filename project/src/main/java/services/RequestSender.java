package services;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import joseObjects.Challenge;
import services.Dns.Dns01Challenge;
import services.Http.Http01Challenge;
import utils.KeyStuff;
import joseObjects.Nonce;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.List;

public class RequestSender {
    public Dns01Challenge dc;
    public Http01Challenge httpc;
    public RequestSender(String DNSServerAddress) throws IOException {
        dc = new Dns01Challenge(DNSServerAddress);
        httpc = new Http01Challenge();
    }
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

        try {
            nonce.setNonce(connection.getHeaderField("Replay-Nonce"));
            if (motivation.equals("newAccount"))
                ks.setLocation(connection.getHeaderField("Location"));

            BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            List<List<String>> certificateLines = new ArrayList<>();
            while ((line = br.readLine()) != null) {
                sb.append(line);
                if (motivation.equals("cert")){
                    if (line.toLowerCase().contains("begin certificate")) {
                        certificateLines.add(new ArrayList<>());
                    } else if (!line.toLowerCase().contains("end certificate")) {
                        certificateLines.get(certificateLines.size() - 1).add(line);
                    }
                }
            }
            if (motivation.equals("cert")) {
                ks.setCertificate(certificateLines);
            }

            br.close();
            if (motivation.equals("newOrder")) {
                JsonReader jsonReader = Json.createReader(new StringReader(sb.toString()));
                JsonObject jObj = jsonReader.readObject();
                ks.setFinalizeUrl(jObj.getString("finalize"));
                javax.json.JsonArray authorizations = jObj.getJsonArray("authorizations");
                List<String> authroizationList= new ArrayList<>();
                for (int i =0; i<authorizations.size();i++) {
                    authroizationList.add(authorizations.getString(i));
                }
                ks.setAuthz(authroizationList);
                ks.setSecondLocation(connection.getHeaderField("Location"));
            }
            if (motivation.equals("finalizeOrder")) {
                JsonReader jsonReader = Json.createReader(new StringReader(sb.toString()));
                JsonObject jObj = jsonReader.readObject();
                ks.setFinalizeUrl(jObj.getString("finalize"));

            }
            if (motivation.equals("authzCheck")) {
                JsonReader jsonReader = Json.createReader(new StringReader(sb.toString()));
                JsonObject jObj = jsonReader.readObject();
                if (jObj.get("status").equals("valid"))
                    ks.getDns01().get(0).setStatus("valid");
            }
            if (motivation.equals("statusCheck")) {
                JsonReader jsonReader = Json.createReader(new StringReader(sb.toString()));
                JsonObject jObj = jsonReader.readObject();
                System.out.println(jObj.toString());
                if (!jObj.getString("status").equals("pending")) {
                    if (jObj.containsKey("certificate")) {
                        ks.setCertificateUrl(jObj.getString("certificate"));
                        ks.setAuthStatus(true);
                    }
                    if (jObj.containsKey("finalize"))
                        ks.setFinalizeUrl(jObj.getString("finalize"));
                    if (jObj.getString("status").equals("ready")) {
                        ks.setReady(true);
                    }
                }
            }

            if (motivation.equals("newAuthz")) {
                com.google.gson.JsonObject jObj = new JsonParser().parse(new StringReader(sb.toString())).getAsJsonObject();
                Gson gson = new Gson();
                System.out.println(jObj);
                JsonArray ja = jObj.getAsJsonArray("challenges");
                for (int i = 0; i <ja.size(); i++) {
                    String challengeType = ja.get(i).getAsJsonObject().get("type").toString();
                    Challenge challenge = gson.fromJson(ja.get(i).toString(), Challenge.class);
                    String domain =jObj.get("identifier").getAsJsonObject().get("value").toString();
                    String cleanDomain = domain.substring(1, domain.length() - 1);
                    challenge.setDomain(cleanDomain);
                    boolean wcard = false;
                    if (jObj.get("wildcard") != null) {
                        String wildcard =jObj.get("wildcard").toString();
                        challenge.setWildcard(wildcard.equals("true"));
                        wcard = wildcard.equals("true");
                    }
                    switch (challengeType) {
                        case "\"http-01\"" -> {
                            ks.setHttp01(challenge);
                            httpc.startHttpChallenge(ks, cleanDomain);
                        }
                        case "\"tls-alpn-01\"" -> ks.setTlsAlpn01(challenge);
                        case "\"dns-01\"" -> {
                            ks.setDns01(challenge);
                            dc.startDnsChallenge(ks, cleanDomain, wcard);
                        }
                        default -> System.out.println("shit challenge");
                    }
                }
            }
            // JsonReader jsonReader = Json.createReader(new StringReader(sb.toString()));
            // JsonObject jObj = jsonReader.readObject();

        } catch (IOException | NoSuchAlgorithmException ioException) {
            /*BufferedReader br = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
                System.out.println(line);
            }*/
            ioException.printStackTrace();
        }
    }
}
