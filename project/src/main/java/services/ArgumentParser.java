package services;

import java.util.ArrayList;
import java.util.List;

public class ArgumentParser {
    public String challengeType;
    public String ACMEServerDirectory;
    public String DNSServerAddress;
    public List<String> domainList = new ArrayList<>();
    public ArgumentParser(String[] arguments) {
        challengeType = arguments[0];
        for(int i  = 1; i < arguments.length; i++) {
            switch (arguments[i]){
                case "--dir":
                    ACMEServerDirectory = arguments[++i];
                    i++;
                case "--record":
                    DNSServerAddress = arguments[++i];
                    i++;
                case "--domain":
                    domainList.add(arguments[++i]);
                    i++;
            }
        }
    }
}
