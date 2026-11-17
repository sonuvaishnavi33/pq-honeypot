package pqh.honeypot;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import pqh.research.DetectionProperties;
import pqh.research.PayloadViews;

/** Sliding-window rules R1,R2,R4..R8. All thresholds come from application.yml. */
@Component @Profile("honeypot")
public class RulesEngine {
  public record Result(int score, String level, List<String> hits) {}
  private final RulesProps p;
  private final DetectionProperties detection;
  private final Map<String, Deque<Long>> fails = new ConcurrentHashMap<>(), reqs = new ConcurrentHashMap<>();
  private final Map<String, Map<String, Long>> users = new ConcurrentHashMap<>();
  private final List<Pattern> inj;
  public RulesEngine(RulesProps p, DetectionProperties detection) {
    this.p = p;
    this.detection = detection;
    inj = p.injection().stream().map(Pattern::compile).toList();
  }

  public synchronized Result evaluate(String ip, String user, String pass, String endpoint, String ua, String payload, boolean failedLogin, long now) {
    List<String> hit = new ArrayList<>();
    if (failedLogin) {
      if (window(fails, ip, now, p.bruteWindowSec()) >= p.bruteThreshold()) hit.add("R1");
      if (user != null) {
        var m = users.computeIfAbsent(ip, k -> new HashMap<>()); m.put(user, now);
        m.values().removeIf(t -> now - t > p.stuffingWindowSec() * 1000L);
        if (m.size() >= p.stuffingUsers()) hit.add("R2");
      }
    }
    if (window(reqs, ip, now, p.rateWindowSec()) > p.rateMax()) hit.add("R4");
    String low = ua == null ? "" : ua.toLowerCase();
    if (p.scanners().stream().anyMatch(low::contains)) hit.add("R5");
    String rawPayload = payload == null ? "" : payload;
    String path = endpoint == null ? "" : endpoint;
    PayloadViews.Views views = PayloadViews.of(rawPayload + " " + path, detection.maxDecodeRounds());
    boolean rawInjection = hasInjection(rawPayload + " " + path);
    PayloadViews.View matched = views.details().stream()
        .filter(view -> hasInjection(view.text())).findFirst().orElse(null);
    if (matched != null) {
      hit.add("R6");
      if (!rawInjection) hit.add("R6D");
      hit.add("R6V=" + matched.kind());
      if (matched.round() > 0) hit.add("R6N=" + matched.round());
    }
    if (views.malformedEncoding()) hit.add("R6M=1");
    if (endpoint != null && p.sensitivePaths().stream().anyMatch(endpoint::startsWith)) hit.add("R7");
    if (user != null && pass != null && p.honeytokens().contains(user + ":" + pass)) hit.add("R8");
    int score = Math.min(100, hit.stream().mapToInt(r -> p.weights().getOrDefault(r, 0)).sum());
    return new Result(score, score >= p.highFrom() ? "HIGH" : score >= p.mediumFrom() ? "MEDIUM" : "LOW", hit);
  }
  private boolean hasInjection(String body) { return inj.stream().anyMatch(x -> x.matcher(body).find()); }
  /** Records an event for this key and returns how many fall inside the window (including this one). */
  private int window(Map<String, Deque<Long>> map, String ip, long now, int sec) {
    Deque<Long> d = map.computeIfAbsent(ip, k -> new ArrayDeque<>()); d.addLast(now);
    while (!d.isEmpty() && now - d.peekFirst() > sec * 1000L) d.pollFirst(); return d.size();
  }
}
