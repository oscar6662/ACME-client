package joseObjects;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static utils.Utils.GenerateKeys;

public class KeyStuff {
    private KeyPair pair;
    private String location;
    private String finalizeUrl;
    private String authz;
    private Challenge tlsAlpn01;
    private Challenge dns01;
    private Challenge http01;
    private String certificateUrl;
    private boolean authStatus;
    private String secondLocation;
    private String certificate;

    public KeyStuff() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
         pair = GenerateKeys();
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

    public String getAuthz() {
        return authz;
    }

    public void setAuthz(String authz) {
        this.authz = authz;
    }

    public Challenge getDns01() {
        return dns01;
    }

    public Challenge getHttp01() {
        return http01;
    }

    public Challenge getTlsAlpn01() {
        return tlsAlpn01;
    }

    public void setDns01(Challenge dns01) {
        this.dns01 = dns01;
    }

    public void setHttp01(Challenge http01) {
        this.http01 = http01;
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

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    public String getCertificate() {
        return certificate;
    }
}
