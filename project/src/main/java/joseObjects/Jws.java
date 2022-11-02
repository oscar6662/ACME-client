package joseObjects;

import com.google.gson.annotations.SerializedName;

public class Jws {
    @SerializedName("protected")
    public String prctd;
    public String payload;
    public String signature;
    public Jws (String prctd, String payload, String signature) {
        this.prctd = prctd;
        this.payload = payload;
        this.signature = signature;
    }
}
