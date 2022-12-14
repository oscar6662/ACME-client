package joseObjects;

public class Challenge {
    private String type;
    private String url;
    private String token;
    private String status;
    private String domain;
    private boolean wildcard = false;
    public Challenge(String type, String url, String token, String status) {
        this.type = type;
        this.url = url;
        this.token = token;
        this.status = status;
    }

    public String getStatus() {
        return status;
    }

    public String getToken() {
        return token;
    }

    public String getType() {
        return type;
    }

    public String getUrl() {
        return url;
    }
    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public boolean isWildcard() {
        return wildcard;
    }

    public void setWildcard(boolean wildcard) {
        this.wildcard = wildcard;
    }
    public void setStatus(String status) {
        this.status = status;
    }
}
