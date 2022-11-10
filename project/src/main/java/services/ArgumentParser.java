package services;

import java.util.ArrayList;
import java.util.List;

public class ArgumentParser {
    public String challengeType;
    public String ACMEServerDirectory;
    public String DNSServerAddress;
    public List<String> domainList = new ArrayList<>();
    public boolean multipleDomains = false;
    public boolean shouldRevoke;
    public ArgumentParser(String[] arguments) {
        challengeType = arguments[0];
        for(int i  = 1; i < arguments.length; i++) {
            switch (arguments[i]) {
                case "--dir":
                    ACMEServerDirectory = arguments[++i];

                    break;
                case "--record":
                    DNSServerAddress = arguments[++i];
                    break;
                case "--domain":
                    domainList.add(arguments[++i]);
                    break;
                case "--revoke":
                    shouldRevoke = true;
                    break;
            }
        }
        if (domainList.size() >1) multipleDomains = true;
    }
}
