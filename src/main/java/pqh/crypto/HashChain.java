package pqh.crypto;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

/** h0 = SHA256("GENESIS"||node); hn = SHA256(h(n-1)||seq||canonical(event)). */
public final class HashChain {
  public record Link(long seq, String canonical, String hash) {}
  private HashChain() {}
  public static String sha(String s) {
    try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8))); }
    catch (Exception e) { throw new IllegalStateException(e); }
  }
  public static String genesis(String nodeId) { return sha("GENESIS" + nodeId); }
  public static String next(String prev, long seq, String canonical) { return sha(prev + seq + canonical); }
  /** Returns index of first broken/out-of-order link, or -1 if the chain verifies. */
  public static int verify(String prev, long expectedFirstSeq, List<Link> links) {
    long seq = expectedFirstSeq;
    for (int i = 0; i < links.size(); i++, seq++) {
      Link l = links.get(i);
      if (l.seq() != seq || !next(prev, l.seq(), l.canonical()).equals(l.hash())) return i;
      prev = l.hash();
    }
    return -1;
  }
}
