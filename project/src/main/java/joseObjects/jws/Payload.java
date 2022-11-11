package joseObjects.jws;

import java.util.List;

public class Payload {
    public boolean termsOfServiceAgreed;
    public String[] contact;

    public Payload(boolean termsOfServiceAgreed, String[] contact) {
        this.termsOfServiceAgreed = termsOfServiceAgreed;
        this.contact = contact;
    }
    public static class PayloadforNewOrder {
        public Identifier[] identifiers;

        public PayloadforNewOrder(List<String> identifiers) {
            this.identifiers = new Identifier[identifiers.size()];
            for(int i = 0; i < identifiers.size(); i++)
                this.identifiers[i] = new Identifier("dns", identifiers.get(i));

        }
    }
    public static class PayloadToFinalizeOrder {
        public String csr;

        public PayloadToFinalizeOrder(String csr) {
            this.csr = csr;
        }
    }
    public static class PayloadToRevoke {
        public String certificate;

        public PayloadToRevoke(String certificate) {
            this.certificate = certificate;
        }
    }
}
