package utils;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class Utils {
    public static byte[] convertDerToConcatenated(byte[] derEncodedBytes, int outputLength) throws IOException
    {
        int offset;
        if (derEncodedBytes[1] > 0) {
            offset = 2;
        } else if (derEncodedBytes[1] == (byte) 0x81) {
            offset = 3;
        } else {
            throw new IOException("Invalid format of ECDSA signature");
        }

        byte rLength = derEncodedBytes[offset + 1];

        int i;
        for (i = rLength; (i > 0) && (derEncodedBytes[(offset + 2 + rLength) - i] == 0); i--);

        byte sLength = derEncodedBytes[offset + 2 + rLength + 1];

        int j;
        for (j = sLength; (j > 0) && (derEncodedBytes[(offset + 2 + rLength + 2 + sLength) - j] == 0); j--);

        int rawLen = Math.max(i, j);
        rawLen = Math.max(rawLen, outputLength/2);

        byte[] concatenatedSignatureBytes = new byte[2*rawLen];

        System.arraycopy(derEncodedBytes, (offset + 2 + rLength) - i, concatenatedSignatureBytes, rawLen - i, i);
        System.arraycopy(derEncodedBytes, (offset + 2 + rLength + 2 + sLength) - j, concatenatedSignatureBytes, 2*rawLen - j, j);

        return concatenatedSignatureBytes;
    }
    public static String serialize(String... parts) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            String part = (parts[i] == null) ? "" : parts[i];
            sb.append(part);
            if (i != parts.length - 1) {
                sb.append(".");
            }
        }
        return sb.toString();
    }
    public static KeyPair GenerateKeys() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("P-256");
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        g.initialize(ecSpec, new SecureRandom());
        return g.generateKeyPair();
    }
    public static byte[] sha256hash(String z) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(z.getBytes(StandardCharsets.UTF_8));
            return md.digest();
        } catch (NoSuchAlgorithmException ex) {
            System.out.println(ex);
            return null;
        }
    }
}
