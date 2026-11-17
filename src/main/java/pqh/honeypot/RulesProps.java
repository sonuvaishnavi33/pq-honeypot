package pqh.honeypot;
import java.util.*;
import org.springframework.boot.context.properties.ConfigurationProperties;
@ConfigurationProperties("app.rules")
public record RulesProps(int bruteWindowSec, int bruteThreshold, int stuffingWindowSec, int stuffingUsers, int rateWindowSec, int rateMax,
    int mediumFrom, int highFrom, Map<String, Integer> weights, List<String> scanners, List<String> injection, List<String> sensitivePaths, List<String> honeytokens) {}
