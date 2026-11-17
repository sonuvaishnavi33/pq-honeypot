package pqh.crypto;
/** One security event. Canonical form is what gets hashed. */
public record Ev(long seq, String time, String ip, String user, String endpoint, String method, String ua, int score, String level, String rules) {
  public String canonical() { return String.join("|", time, ip, n(user), n(endpoint), n(method), n(ua), "" + score, level, n(rules)); }
  private static String n(String s) { return s == null ? "" : s; }
  public record Rec(Ev ev, String hash) {}
}
