package pqh.honeypot;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import pqh.research.DetectionProperties;

class RulesEngineTest {
  private static final List<String> INJECTION_PATTERNS = List.of(
      "(?i)union\\s+select",
      "(?i)un\\s+ion\\s+select",
      "(?i)<script",
      "\\.\\./",
      "(?i);\\s*(cat|ls|wget|curl)\\s",
      "(?i)'\\s*or\\s+'?1'?='?1");

  @Test
  void detectsEncodedIndicatorsWithoutFlaggingBenignEncodedQueries() {
    List<String> positive = List.of(
        "probe=union%20select%20local_test",
        "probe=%3Cscript%3E",
        "probe=..%2Fetc%2Fpasswd",
        "probe=%3B%20cat%20/etc/passwd",
        "probe=%27%20OR%20%271%27%3D%271");
    List<String> benign = List.of(
        "username=alice&city=summer%20weather",
        "q=select%20something",
        "redirect=%2Fhome%2Fprofile",
        "value=100%25",
        "message=one%20two");

    long detected = positive.stream().filter(this::matchesInjection).count();
    long decodedOnly = positive.stream().filter(this::hasDecodedOnlyEvidence).count();
    long falsePositives = benign.stream().filter(this::matchesInjection).count();

    assertEquals(positive.size(), detected);
    assertEquals(positive.size(), decodedOnly);
    assertEquals(0, falsePositives);
  }

  @Test
  void malformedEncodingDoesNotSuppressRawInjectionMatch() {
    var result = evaluate("probe=../safe%ZZ");
    assertTrue(result.hits().contains("R6"));
    assertFalse(result.hits().contains("R6D"));
  }

  @Test
  void rawAndDecodedMatchesHaveEqualRiskButDifferentProvenance() {
    var encoded = evaluate("probe=union%20select%20local_test");
    var raw = evaluate("probe=union select local_test");

    assertEquals(encoded.score(), raw.score());
    assertTrue(encoded.hits().contains("R6D"));
    assertFalse(raw.hits().contains("R6D"));
  }

  @Test
  void repeatedDecodingAndCommentNormalizationAreBoundedAndRecorded() {
    var doubleEncoded = evaluate("probe=union%2520select%2520local_test");
    var commentObfuscated = evaluate("probe=UN/**/ION/**/SELECT");

    assertTrue(doubleEncoded.hits().contains("R6D"));
    assertTrue(doubleEncoded.hits().contains("R6N=2"));
    assertTrue(commentObfuscated.hits().contains("R6D"));
    assertTrue(commentObfuscated.hits().contains("R6V=comments-spaced"));
  }

  @Test
  void dashboardSampleScenariosHaveExpectedRiskAndSignals() {
    RulesEngine engine = new RulesEngine(new RulesProps(
        60, 5, 300, 10, 10, 30, 30, 60,
        Map.of("R1", 40, "R2", 30, "R4", 20, "R5", 20, "R6", 30, "R6D", 0, "R7", 15, "R8", 50),
        List.of("sqlmap", "nikto", "nmap", "hydra", "masscan"),
        INJECTION_PATTERNS,
        List.of("/.env", "/admin", "/phpmyadmin", "/.git"),
        List.of("admin:Passw0rd!", "root:toor")),
        new DetectionProperties(3));

    var benign = engine.evaluate("192.0.2.10", null, null, "/health", "Mozilla/5.0", null, false, 1L);
    var scanner = engine.evaluate("192.0.2.11", null, null, "/health", "sqlmap/1.7", null, false, 1L);
    var injection = engine.evaluate("192.0.2.12", null, null, "/.env", "sqlmap/1.7",
        "id=1' OR '1'='1", false, 1L);

    assertEquals(0, benign.score());
    assertEquals("LOW", benign.level());
    assertTrue(benign.hits().isEmpty());
    assertEquals(20, scanner.score());
    assertEquals("LOW", scanner.level());
    assertEquals(List.of("R5"), scanner.hits());
    assertEquals(65, injection.score());
    assertEquals("HIGH", injection.level());
    assertTrue(injection.hits().containsAll(List.of("R5", "R6", "R7")));
  }

  private boolean matchesInjection(String payload) {
    return evaluate(payload).hits().contains("R6");
  }

  private boolean hasDecodedOnlyEvidence(String payload) {
    return evaluate(payload).hits().contains("R6D");
  }

  private RulesEngine.Result evaluate(String payload) {
    RulesProps props = new RulesProps(
        60, 5, 300, 10, 10, 30, 30, 60,
        Map.of("R1", 40, "R2", 30, "R4", 20, "R5", 20, "R6", 30, "R6D", 0, "R7", 15, "R8", 50),
        List.of("sqlmap", "nikto", "nmap", "hydra", "masscan"),
        INJECTION_PATTERNS,
        List.of("/.env", "/admin", "/phpmyadmin", "/.git"),
        List.of("admin:Passw0rd!", "root:toor"));
    return new RulesEngine(props, new DetectionProperties(3))
        .evaluate("192.0.2.1", null, null, "/search", "Mozilla/5.0", payload, false, 1L);
  }
}
