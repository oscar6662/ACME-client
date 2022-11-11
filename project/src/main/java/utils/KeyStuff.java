package utils;

import joseObjects.Challenge;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.List;
import static utils.Utils.GenerateKeys;

public class KeyStuff {
    private KeyPair pair;
    private String location;
    private String finalizeUrl;
    private List<String> authz;
    private Challenge tlsAlpn01;
    private List<Challenge> dns01 = new ArrayList<>();
    private List<Challenge> http01 = new ArrayList<>();
    private String certificateUrl;
    private boolean authStatus = false;
    private String secondLocation;
    private List<List<String>>  certificate;
    private boolean ready = false;

    public KeyStuff() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
         pair = GenerateKeys();
    }
    public int getIndexforDns(String domain, boolean wildcard) {
        for (int i = 0;i<dns01.size(); i++) {
            if (dns01.get(i).getDomain().equals(domain) && wildcard == dns01.get(i).isWildcard()){
                return i;
            }
        }
        return -1;
    }
    public int getIndexforhttp(String domain) {
        for (int i = 0;i<http01.size(); i++) {
            if (http01.get(i).getDomain().equals(domain)){
                return i;
            }
        }
        return -1;
    }

    public KeyPair getPair() {
        return pair;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public String getLocation() {
        return location;
    }

    public void setFinalizeUrl(String finalizeUrl) {
        this.finalizeUrl = finalizeUrl;
    }

    public String getFinalizeUrl() {
        return finalizeUrl;
    }

    public List<String> getAuthz() {
        return authz;
    }

    public void setAuthz(List<String> authz) {
        this.authz = authz;
    }

    public List<Challenge> getDns01() {
        return dns01;
    }

    public List<Challenge> getHttp01() {
        return http01;
    }

    public Challenge getTlsAlpn01() {
        return tlsAlpn01;
    }

    public void setDns01(Challenge dns01) {
        this.dns01.add(dns01);
    }

    public void setHttp01(Challenge http01) {
        this.http01.add(http01);
    }

    public void setTlsAlpn01(Challenge tlsAlpn01) {
        this.tlsAlpn01 = tlsAlpn01;
    }

    public void setCertificateUrl(String certificateUrl) {
        this.certificateUrl = certificateUrl;
    }

    public String getCertificateUrl() {
        return certificateUrl;
    }

    public boolean isAuthStatus() {
        return authStatus;
    }

    public void setAuthStatus(boolean authStatus) {
        this.authStatus = authStatus;
    }

    public String getSecondLocation() {
        return secondLocation;
    }

    public void setSecondLocation(String secondLocation) {
        this.secondLocation = secondLocation;
    }

    public void setCertificate(List<List<String>>  certificate) {
        this.certificate = certificate;
    }

    public List<List<String>>  getCertificate() {
        return certificate;
    }

    public boolean isReady() {
        return ready;
    }

    public void setReady(boolean ready) {
        this.ready = ready;
    }
}
