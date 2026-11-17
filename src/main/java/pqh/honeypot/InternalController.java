package pqh.honeypot;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import pqh.crypto.Ev;

/** Dashboard API: stats, simulation, tamper demo, self-tests. */
@RestController @RequestMapping("/internal") @Profile("honeypot")
public class InternalController {
  private final EventService events; private final ForwardService fwd; private final SelfTestService tests; private final boolean demo;
  public InternalController(EventService e, ForwardService f, SelfTestService t, @Value("${app.demo-mode}") boolean demo) { events = e; fwd = f; tests = t; this.demo = demo; }

  @GetMapping("/overview")
  public Map<String, Object> overview() {
    Map<String, Object> collector;
    try { collector = fwd.client().get().uri("/api/stats").retrieve().body(Map.class); } catch (Exception ex) { collector = Map.of("error", "collector unreachable"); }
    return Map.of("stats", events.stats(), "events", events.recent(25), "lastTransfer", fwd.lastStatus(), "collector", collector,
        "demoMode", demo, "customSimulationAvailable", true);
  }
  @PostMapping("/simulate/custom")
  public Ev simulateCustom(@RequestBody CustomSimulationRequest request) {
    if (!demo) throw new ResponseStatusException(HttpStatus.FORBIDDEN, "custom simulation requires demo mode");
    if (request == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "simulation data is required");

    String ip = clean(request.sourceIp(), "sourceIp", 45, true);
    if (!isIpAddress(ip)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "sourceIp must be a valid IPv4 or IPv6 value");
    String username = clean(request.username(), "username", 64, false);
    String endpoint = clean(request.endpoint(), "endpoint", 200, true);
    if (!endpoint.startsWith("/") || endpoint.startsWith("//")) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "endpoint must be a local path starting with one slash");
    String method = clean(request.method(), "method", 10, true).toUpperCase(Locale.ROOT);
    if (!Set.of("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD").contains(method)) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "method must be GET, POST, PUT, PATCH, DELETE, or HEAD");
    }
    String userAgent = clean(request.userAgent(), "userAgent", 160, false);
    String payload = clean(request.payload(), "payload", 512, false);
    return events.record(ip, username, null, endpoint, method, userAgent, payload, request.failedLogin());
  }

  public record CustomSimulationRequest(String sourceIp, String username, String endpoint, String method,
                                        String userAgent, String payload, boolean failedLogin) {}

  @PostMapping("/simulate/{kind}")
  public String simulate(@PathVariable String kind) {
    String ip = "203.0.113." + (1 + new Random().nextInt(200));
    switch (kind) {
      case "bruteforce" -> { for (int i = 0; i < 8; i++) events.record(ip, "admin", "pw" + i, "/login", "POST", "hydra/9.4", null, true); }
      case "scanner" -> { for (String p : List.of("/.env", "/phpmyadmin", "/.git/config", "/admin")) events.record(ip, null, null, p, "GET", "sqlmap/1.7", "id=1' OR '1'='1", false); }
      case "honeytoken" -> events.record(ip, "admin", "Passw0rd!", "/login", "POST", "curl/8", null, true);
      default -> { events.record("198.51.100.7", "alice", "typo1", "/login", "POST", "Mozilla/5.0", null, true); }
    }
    return "simulated " + kind + " from " + ip;
  }
  @PostMapping("/forward") public String forward() throws Exception { return fwd.forward(); }
  @PostMapping("/demo/tamper") public String tamper() { guard(); events.tamperOne(); return "Edited newest pending row directly in DB (hash NOT updated). Now click Forward."; }
  @PostMapping("/demo/reset")
  public String reset() {
    guard();
    events.reset();
    fwd.resetSession();
    fwd.client().post().uri("/api/reset").retrieve().toBodilessEntity();
    return "reset";
  }
  @PostMapping("/selftest") public List<SelfTestService.Result> selftest() { return tests.runAll(); }
  private void guard() { if (!demo) throw new IllegalStateException("demo-mode is off"); }

  private String clean(String value, String field, int maxLength, boolean required) {
    String cleaned = value == null ? "" : value.trim();
    if (required && cleaned.isEmpty()) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, field + " is required");
    if (cleaned.length() > maxLength) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, field + " is too long");
    if (cleaned.chars().anyMatch(Character::isISOControl)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, field + " contains invalid characters");
    return cleaned.isEmpty() ? null : cleaned;
  }

  private boolean isIpAddress(String value) {
    if (value.indexOf(':') >= 0) {
      try { return InetAddress.getByName(value) instanceof Inet6Address; }
      catch (UnknownHostException ex) { return false; }
    }
    String[] octets = value.split("\\.", -1);
    if (octets.length != 4) return false;
    for (String octet : octets) {
      if (!octet.matches("\\d{1,3}") || Integer.parseInt(octet) > 255) return false;
    }
    return true;
  }
}
