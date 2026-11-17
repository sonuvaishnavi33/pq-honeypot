package pqh.honeypot;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import pqh.crypto.*;
import pqh.research.DetectionProperties;

/** Runs the security test cases live so the dashboard can show pass/fail. Same checks as the JUnit suite. */
@Service @Profile("honeypot")
public class SelfTestService {
  public record Result(String name, boolean pass, String detail) {}
  private final CryptoService c; private final RulesProps props; private final DetectionProperties detection;
  public SelfTestService(CryptoService c, RulesProps p, DetectionProperties detection) {
    this.c = c; this.props = p; this.detection = detection;
  }
  private static byte[] b(String s) { return s.getBytes(StandardCharsets.UTF_8); }
  private static byte[] hex(String s) { return HexFormat.of().parseHex(s); }

  public List<Result> runAll() {
    List<Result> out = new ArrayList<>();
    t(out, "ML-KEM-768: both sides derive same secret", () -> { var kp = c.kemKeyPair(); var e = c.encapsulate(kp.getPublic()); return Arrays.equals(e.secret(), c.decapsulate(kp.getPrivate(), e.ciphertext())); });
    t(out, "HKDF matches RFC 5869 test vector 1", () -> {
      byte[] ikm = new byte[22]; Arrays.fill(ikm, (byte) 0x0b);
      return HexFormat.of().formatHex(c.hkdf(ikm, hex("000102030405060708090a0b0c"), hex("f0f1f2f3f4f5f6f7f8f9"), 42)).equals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"); });
    byte[] key = new byte[32]; new Random().nextBytes(key); byte[] n = c.nonce(new byte[4], 1), aad = b("aad");
    t(out, "AES-GCM round trip", () -> Arrays.equals(c.open(key, n, aad, c.seal(key, n, aad, b("log"))), b("log")));
    t(out, "Flip one ciphertext byte -> TAMPERED", () -> rejects(() -> { byte[] ct = c.seal(key, n, aad, b("log")); ct[0] ^= 1; c.open(key, n, aad, ct); }));
    t(out, "Modified AAD -> rejected", () -> rejects(() -> c.open(key, n, b("other"), c.seal(key, n, aad, b("log")))));
    t(out, "Wrong key -> rejected", () -> rejects(() -> { byte[] k2 = key.clone(); k2[0] ^= 1; c.open(k2, n, aad, c.seal(key, n, aad, b("log"))); }));
    t(out, "Counter nonces never repeat", () -> !Arrays.equals(c.nonce(new byte[4], 1), c.nonce(new byte[4], 2)));
    List<HashChain.Link> chain = build(5);
    t(out, "Hash chain: valid chain verifies", () -> HashChain.verify("g", 1, chain) == -1);
    t(out, "Hash chain: edited record detected", () -> { var l = new ArrayList<>(chain); l.set(2, new HashChain.Link(3, "evil", l.get(2).hash())); return HashChain.verify("g", 1, l) == 2; });
    t(out, "Hash chain: deleted record detected", () -> { var l = new ArrayList<>(chain); l.remove(2); return HashChain.verify("g", 1, l) >= 0; });
    t(out, "Hash chain: swapped records detected", () -> { var l = new ArrayList<>(chain); Collections.swap(l, 1, 3); return HashChain.verify("g", 1, l) >= 0; });
    t(out, "Rule R1 fires at threshold, not below", () -> {
      var e = new RulesEngine(props, detection); RulesEngine.Result r = null; boolean below = true; long now = System.currentTimeMillis();
      for (int i = 1; i <= props.bruteThreshold(); i++) { r = e.evaluate("9.9.9.9", "u", "p", "/login", "Mozilla", null, true, now + i); if (i < props.bruteThreshold() && r.hits().contains("R1")) below = false; }
      return below && r.hits().contains("R1"); });
    t(out, "Rule R5/R6/R8 (scanner UA, injection, honeytoken)", () -> {
      var e = new RulesEngine(props, detection); long now = System.currentTimeMillis();
      return e.evaluate("1.1.1.1", null, null, "/x", "sqlmap", "id=1 union select 1", false, now).hits().containsAll(List.of("R5", "R6"))
          && e.evaluate("1.1.1.2", "admin", "Passw0rd!", "/login", "x", null, true, now).hits().contains("R8"); });
    t(out, "Rule R6 detects percent-encoded injection", () ->
        new RulesEngine(props, detection).evaluate("2.2.2.1", null, null, "/search", "Mozilla/5.0",
            "probe=union%20select%20test", false, System.currentTimeMillis()).hits().contains("R6"));
    t(out, "Rule R6D marks decoded-only evidence without changing score", () -> {
      var e = new RulesEngine(props, detection); long now = System.currentTimeMillis();
      var encoded = e.evaluate("2.2.2.4", null, null, "/search", "Mozilla/5.0",
          "probe=union%20select%20test", false, now);
      var raw = e.evaluate("2.2.2.5", null, null, "/search", "Mozilla/5.0",
          "probe=union select test", false, now);
      return encoded.hits().containsAll(List.of("R6", "R6D"))
          && !raw.hits().contains("R6D")
          && encoded.score() == raw.score();
    });
    t(out, "Rule R6 excludes benign encoded input", () ->
        !new RulesEngine(props, detection).evaluate("2.2.2.2", null, null, "/search", "Mozilla/5.0",
            "city=summer%20weather", false, System.currentTimeMillis()).hits().contains("R6"));
    t(out, "Malformed encoding preserves raw rule matching", () ->
        new RulesEngine(props, detection).evaluate("2.2.2.3", null, null, "/search", "Mozilla/5.0",
            "probe=../safe%ZZ", false, System.currentTimeMillis()).hits().contains("R6"));
    return out;
  }
  private List<HashChain.Link> build(int n) {
    List<HashChain.Link> l = new ArrayList<>(); String prev = "g";
    for (int i = 1; i <= n; i++) { String h = HashChain.next(prev, i, "e" + i); l.add(new HashChain.Link(i, "e" + i, h)); prev = h; } return l;
  }
  interface Thrower { void run() throws Exception; }
  private boolean rejects(Thrower t) { try { t.run(); return false; } catch (Exception e) { return true; } }
  interface Check { boolean ok() throws Exception; }
  private void t(List<Result> out, String name, Check ch) {
    try { boolean ok = ch.ok(); out.add(new Result(name, ok, ok ? "passed" : "FAILED")); } catch (Exception e) { out.add(new Result(name, false, e.toString())); }
  }
}
