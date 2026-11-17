package pqh.research;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Bounded URL decoding and normalization views for the request-rule evaluator. */
public final class PayloadViews {
  private PayloadViews() {}

  public record View(String kind, int round, String text) {}
  public record Views(Set<String> texts, List<View> details, int decodeRounds, boolean malformedEncoding) {}

  public static Views of(String raw, int maxRounds) {
    if (maxRounds < 0) throw new IllegalArgumentException("maxRounds must be non-negative");
    String initial = raw == null ? "" : raw;
    Set<String> views = new LinkedHashSet<>();
    List<View> details = new ArrayList<>();
    views.add(initial);
    details.add(new View("raw", 0, initial));
    String current = initial;
    int rounds = 0;
    boolean malformed = false;
    for (int i = 0; i < maxRounds; i++) {
      String decoded;
      try {
        decoded = URLDecoder.decode(current, StandardCharsets.UTF_8);
      } catch (IllegalArgumentException ex) {
        malformed = true;
        break;
      }
      if (decoded.equals(current)) break;
      current = decoded;
      rounds++;
      views.add(current);
      details.add(new View("percent-decoded", rounds, current));
    }
    String lower = current.toLowerCase(Locale.ROOT);
    views.add(lower);
    details.add(new View("lowercase", rounds, lower));
    String commentsRemoved = lower.replaceAll("/\\*.*?\\*/", "");
    views.add(commentsRemoved);
    details.add(new View("comments-removed", rounds, commentsRemoved));
    String commentsSpaced = lower.replaceAll("/\\*.*?\\*/", " ");
    views.add(commentsSpaced);
    details.add(new View("comments-spaced", rounds, commentsSpaced));
    String whitespaceCollapsed = lower.replaceAll("\\s+", " ");
    views.add(whitespaceCollapsed);
    details.add(new View("whitespace-collapsed", rounds, whitespaceCollapsed));
    return new Views(Set.copyOf(views), List.copyOf(details), rounds, malformed);
  }
}
