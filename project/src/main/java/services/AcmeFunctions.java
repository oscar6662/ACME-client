package services;

import com.google.gson.Gson;
import joseObjects.Jwk;
import joseObjects.Jws;
import joseObjects.KeyStuff;
import joseObjects.jws.Payload;
import joseObjects.jws.Protected;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.List;

import static utils.Utils.*;
import joseObjects.Nonce;

public class AcmeFunctions {
    private Nonce nonce;
    private String NEW_ACCOUNT_URL;
    private String NEW_ORDER_URL;
    private requestSender rs;
    private KeyStuff ks;
    private Gson gson;
    public AcmeFunctions(Nonce nonce, String newAccUrl, String newOrderUrl, String DNSServerAddress) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        this.nonce = nonce;
        NEW_ACCOUNT_URL = newAccUrl;
        NEW_ORDER_URL = newOrderUrl;
        rs = new requestSender(DNSServerAddress);
        ks = new KeyStuff();
        gson = new Gson();

    }
        public void newAccount() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException
        {
            Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
            ecdsaSign.initSign(ks.getPair().getPrivate());

            Jwk jwk = new Jwk("EC", "P-256", Base64.encodeBase64URLSafeString(((ECPublicKey) ks.getPair().getPublic()).getQ().getAffineXCoord().getEncoded()), Base64.encodeBase64URLSafeString(((ECPublicKey) ks.getPair().getPublic()).getQ().getAffineYCoord().getEncoded()));
            Protected p = new Protected("ES256", jwk, nonce.getNonce(), NEW_ACCOUNT_URL);
            String pString = gson.toJson(p);
            byte[] by = pString.getBytes("UTF-8");

            String [] a = new String[1];
            a[0] = "mailto:something@something.com";
            Payload payload = new Payload(true, a);

            String payloadString = gson.toJson(payload);
            byte[] bz = payloadString.getBytes("UTF-8");

            String baba = serialize(Base64.encodeBase64URLSafeString(by), Base64.encodeBase64URLSafeString(bz));
            ecdsaSign.update(baba.getBytes("UTF-8"));
            byte[] signature = ecdsaSign.sign();
            byte[] formatsign = convertDerToConcatenated(signature, 16);
            Jws jws = new Jws(Base64.encodeBase64URLSafeString(by),Base64.encodeBase64URLSafeString(bz), Base64.encodeBase64URLSafeString(formatsign));
            String jwsString = gson.toJson(jws);
            rs.sendPost(NEW_ACCOUNT_URL, jwsString, nonce, ks, "newAccount");
        }

    public void newOrder(List<String> identifiers) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IOException, SignatureException {
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaSign.initSign(ks.getPair().getPrivate());

        Protected p = new Protected("ES256", ks.getLocation(), nonce.getNonce(), NEW_ORDER_URL);
        byte[] by = gson.toJson(p).getBytes("UTF-8");

        Payload.PayloadforNewOrder pn = new Payload.PayloadforNewOrder(identifiers);
        byte[] bz = gson.toJson(pn).getBytes("UTF-8");

        String baba = serialize(Base64.encodeBase64URLSafeString(by), Base64.encodeBase64URLSafeString(bz));
        ecdsaSign.update(baba.getBytes("UTF-8"));

        byte[] signature = ecdsaSign.sign();
        byte[] formatsign = convertDerToConcatenated(signature, 16);
        Jws jws = new Jws(Base64.encodeBase64URLSafeString(by),Base64.encodeBase64URLSafeString(bz), Base64.encodeBase64URLSafeString(formatsign));

        String jwsString = gson.toJson(jws);
        rs.sendPost(NEW_ORDER_URL, jwsString, nonce, ks, "newOrder");
    }

    public void newAuthz() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IOException, SignatureException{
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaSign.initSign(ks.getPair().getPrivate());

        Protected p = new Protected("ES256", ks.getLocation(), nonce.getNonce(), ks.getAuthz());
        byte[] by = gson.toJson(p).getBytes("UTF-8");

        String baba = serialize(Base64.encodeBase64URLSafeString(by), "");
        ecdsaSign.update(baba.getBytes("UTF-8"));

        byte[] signature = ecdsaSign.sign();
        byte[] formatsign = convertDerToConcatenated(signature, 16);
        Jws jws = new Jws(Base64.encodeBase64URLSafeString(by),"", Base64.encodeBase64URLSafeString(formatsign));

        String jwsString = gson.toJson(jws);
        rs.sendPost(ks.getAuthz(), jwsString, nonce, ks, "newAuthz");
    }
    public void dns01() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IOException, SignatureException{
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaSign.initSign(ks.getPair().getPrivate());

        Protected p = new Protected("ES256", ks.getLocation(), nonce.getNonce(), ks.getDns01().getUrl());
        byte[] by = gson.toJson(p).getBytes("UTF-8");

        String baba = serialize(Base64.encodeBase64URLSafeString(by), Base64.encodeBase64URLSafeString("{}".getBytes(StandardCharsets.UTF_8)));
        ecdsaSign.update(baba.getBytes("UTF-8"));

        byte[] signature = ecdsaSign.sign();
        byte[] formatsign = convertDerToConcatenated(signature, 16);
        Jws jws = new Jws(Base64.encodeBase64URLSafeString(by),Base64.encodeBase64URLSafeString("{}".getBytes(StandardCharsets.UTF_8)), Base64.encodeBase64URLSafeString(formatsign));

        String jwsString = gson.toJson(jws);
        rs.sendPost(ks.getDns01().getUrl(), jwsString, nonce, ks, "dns01");

    }
    public void http01() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IOException, SignatureException{
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaSign.initSign(ks.getPair().getPrivate());

        Protected p = new Protected("ES256", ks.getLocation(), nonce.getNonce(), ks.getHttp01().getUrl());
        byte[] by = gson.toJson(p).getBytes("UTF-8");

        String baba = serialize(Base64.encodeBase64URLSafeString(by), Base64.encodeBase64URLSafeString("{}".getBytes(StandardCharsets.UTF_8)));
        ecdsaSign.update(baba.getBytes("UTF-8"));

        byte[] signature = ecdsaSign.sign();
        byte[] formatsign = convertDerToConcatenated(signature, 16);
        Jws jws = new Jws(Base64.encodeBase64URLSafeString(by),Base64.encodeBase64URLSafeString("{}".getBytes(StandardCharsets.UTF_8)), Base64.encodeBase64URLSafeString(formatsign));

        String jwsString = gson.toJson(jws);
        rs.sendPost(ks.getHttp01().getUrl(), jwsString, nonce, ks, "http01");
    }
    public void tls01() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IOException, SignatureException{
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaSign.initSign(ks.getPair().getPrivate());

        Protected p = new Protected("ES256", ks.getLocation(), nonce.getNonce(), ks.getTlsAlpn01().getUrl());
        byte[] by = gson.toJson(p).getBytes("UTF-8");

        String baba = serialize(Base64.encodeBase64URLSafeString(by), Base64.encodeBase64URLSafeString("{}".getBytes(StandardCharsets.UTF_8)));
        ecdsaSign.update(baba.getBytes("UTF-8"));

        byte[] signature = ecdsaSign.sign();
        byte[] formatsign = convertDerToConcatenated(signature, 16);
        Jws jws = new Jws(Base64.encodeBase64URLSafeString(by),Base64.encodeBase64URLSafeString("{}".getBytes(StandardCharsets.UTF_8)), Base64.encodeBase64URLSafeString(formatsign));

        String jwsString = gson.toJson(jws);
        rs.sendPost(ks.getTlsAlpn01().getUrl(), jwsString, nonce, ks, "tls01");
    }
    public void finalizeOrder(List<String> identifiers) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IOException, OperatorCreationException, SignatureException, InvalidAlgorithmParameterException {
        KeyStuff ks2 = new KeyStuff();
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaSign.initSign(ks.getPair().getPrivate());
        GeneralName[] gns = new GeneralName[1];
        gns[0] = new GeneralName(GeneralName.dNSName, "example.org");
        GeneralNames subjectAltName = new GeneralNames(gns);

        Protected p = new Protected("ES256", ks.getLocation(), nonce.getNonce(), ks.getFinalizeUrl());
        byte[] by = gson.toJson(p).getBytes("UTF-8");
        X500NameBuilder namebuilder = new X500NameBuilder(X500Name.getDefaultStyle());
        for(int i = 0; i<identifiers.size(); i++)
            namebuilder.addRDN(BCStyle.CN, IDN.toASCII(identifiers.get(i).trim()).toLowerCase());
        PKCS10CertificationRequestBuilder p10Builder =
                new JcaPKCS10CertificationRequestBuilder(namebuilder.build(), ks2.getPair().getPublic());
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, subjectAltName);

        p10Builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        PrivateKey pk = ks.getPair().getPrivate();
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
        ContentSigner signer = csBuilder.build(pk);

        PKCS10CertificationRequest csr = p10Builder.build(signer);
        Payload.PayloadToFinalizeOrder py = new Payload.PayloadToFinalizeOrder(Base64.encodeBase64URLSafeString(csr.getEncoded()));
        byte[] bz = gson.toJson(py).getBytes("UTF-8");

        String baba = serialize(Base64.encodeBase64URLSafeString(by), Base64.encodeBase64URLSafeString(bz));
        ecdsaSign.update(baba.getBytes("UTF-8"));

        byte[] signature = ecdsaSign.sign();
        byte[] formatsign = convertDerToConcatenated(signature, 16);
        Jws jws = new Jws(Base64.encodeBase64URLSafeString(by),Base64.encodeBase64URLSafeString(bz), Base64.encodeBase64URLSafeString(formatsign));

        String jwsString = gson.toJson(jws);
        rs.sendPost(ks.getFinalizeUrl(), jwsString, nonce, ks, "finalizeOrder");

    }
}
