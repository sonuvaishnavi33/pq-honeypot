package pqh.research;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** HMAC-SHA-256 ratchet for locally sealed evidence epochs. */
public final class ForwardSecureSeal {
  private ForwardSecureSeal() {}

  public record Epoch(long epoch, long firstSeq, long lastSeq, String chainHead, String tag) {}
  public enum Result { OK, BAD_TAG, REPLAYED_EPOCH, EPOCH_GAP }
  public record State(byte[] key, long epoch, byte[] previousTag) {
    public State {
      key = key.clone();
      previousTag = previousTag.clone();
    }
    @Override public byte[] key() { return key.clone(); }
    @Override public byte[] previousTag() { return previousTag.clone(); }
  }

  public static final class Sealer implements AutoCloseable {
    private byte[] key;
    private long epoch;
    private byte[] previousTag = new byte[32];

    public Sealer(byte[] streamSeed) {
      if (streamSeed == null || streamSeed.length < 16) throw new IllegalArgumentException("stream seed too short");
      key = mac(streamSeed, "ratchet/k0", new byte[0]);
    }

    public Sealer(State restored) {
      if (restored == null || restored.key().length != 32 || restored.previousTag().length != 32
          || restored.epoch() < 0) {
        throw new IllegalArgumentException("invalid sealer state");
      }
      key = restored.key();
      epoch = restored.epoch();
      previousTag = restored.previousTag();
    }

    public synchronized Epoch seal(String nodeId, long firstSeq, long lastSeq, String chainHead) {
      if (firstSeq < 1 || lastSeq < firstSeq) throw new IllegalArgumentException("invalid sequence range");
      byte[] tag = mac(key, "mac", message(nodeId, epoch, firstSeq, lastSeq, chainHead, previousTag));
      Epoch sealed = new Epoch(epoch, firstSeq, lastSeq, chainHead, HexFormat.of().formatHex(tag));
      byte[] next = mac(key, "next", new byte[0]);
      Arrays.fill(key, (byte) 0);
      key = next;
      Arrays.fill(previousTag, (byte) 0);
      previousTag = tag;
      epoch++;
      return sealed;
    }

    public synchronized long nextEpoch() { return epoch; }

    public synchronized State exportState() { return new State(key, epoch, previousTag); }

    synchronized byte[] leakCurrentKeyForAttackSimulation() { return key.clone(); }

    @Override public synchronized void close() {
      Arrays.fill(key, (byte) 0);
      Arrays.fill(previousTag, (byte) 0);
    }
  }

  public static final class Verifier implements AutoCloseable {
    private byte[] key;
    private long epoch;
    private byte[] previousTag = new byte[32];

    public Verifier(byte[] streamSeed) {
      if (streamSeed == null || streamSeed.length < 16) throw new IllegalArgumentException("stream seed too short");
      key = mac(streamSeed, "ratchet/k0", new byte[0]);
    }

    public Verifier(State restored) {
      key = restored.key();
      epoch = restored.epoch();
      previousTag = restored.previousTag();
    }

    public synchronized Result verify(String nodeId, Epoch sealed) {
      if (sealed.epoch() < epoch) return Result.REPLAYED_EPOCH;
      if (sealed.epoch() > epoch) return Result.EPOCH_GAP;
      byte[] expected = mac(key, "mac", message(nodeId, sealed.epoch(), sealed.firstSeq(),
          sealed.lastSeq(), sealed.chainHead(), previousTag));
      byte[] given;
      try {
        given = HexFormat.of().parseHex(sealed.tag());
      } catch (IllegalArgumentException ex) {
        return Result.BAD_TAG;
      }
      if (!MessageDigest.isEqual(expected, given)) return Result.BAD_TAG;
      byte[] next = mac(key, "next", new byte[0]);
      Arrays.fill(key, (byte) 0);
      Arrays.fill(previousTag, (byte) 0);
      key = next;
      previousTag = expected;
      epoch++;
      return Result.OK;
    }

    public synchronized State exportState() { return new State(key, epoch, previousTag); }

    @Override public synchronized void close() {
      Arrays.fill(key, (byte) 0);
      Arrays.fill(previousTag, (byte) 0);
    }
  }

  static Epoch forgeForSimulation(byte[] stolenKey, String nodeId, long epoch, long first,
                                  long last, String head, byte[] previousTag) {
    byte[] tag = mac(stolenKey, "mac", message(nodeId, epoch, first, last, head, previousTag));
    return new Epoch(epoch, first, last, head, HexFormat.of().formatHex(tag));
  }

  private static byte[] message(String nodeId, long epoch, long first, long last,
                                String head, byte[] previousTag) {
    try {
      ByteArrayOutputStream buffer = new ByteArrayOutputStream();
      DataOutputStream out = new DataOutputStream(buffer);
      for (String value : new String[] {nodeId, String.valueOf(epoch), String.valueOf(first),
          String.valueOf(last), head}) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
      }
      out.writeInt(previousTag.length);
      out.write(previousTag);
      return buffer.toByteArray();
    } catch (IOException ex) {
      throw new UncheckedIOException(ex);
    }
  }

  static byte[] mac(byte[] key, String label, byte[] data) {
    try {
      Mac hmac = Mac.getInstance("HmacSHA256");
      hmac.init(new SecretKeySpec(key, "HmacSHA256"));
      hmac.update(label.getBytes(StandardCharsets.UTF_8));
      hmac.update((byte) 0);
      return hmac.doFinal(data);
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("HMAC-SHA-256 unavailable", ex);
    }
  }
}
