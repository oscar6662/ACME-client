package joseObjects.jws;

import java.sql.Array;

public class Payload {
    public boolean termsOfServiceAgreed;
    public String[] contact;

    public Payload(boolean termsOfServiceAgreed, String[] contact) {
        this.termsOfServiceAgreed = termsOfServiceAgreed;
        this.contact = contact;
    }
    public static class PayloadforNewOrder {
        public Identifier[] identifiers;

        public PayloadforNewOrder(String type, String value) {
            this.identifiers = new Identifier[1];
            this.identifiers[0] = new Identifier(type, value);
        }
    }
    public static class PayloadToFinalizeOrder {
        public String csr;

        public PayloadToFinalizeOrder(String csr) {
            this.csr = csr;
        }
    }
}
