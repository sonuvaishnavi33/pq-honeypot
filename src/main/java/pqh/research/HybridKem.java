package pqh.research;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.KEM;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/** Classical, post-quantum, and hybrid key establishment modes for evaluation. */
public final class HybridKem {
  public enum Mode { X25519, ML_KEM_768, HYBRID }
  public record ServerKeys(KeyPair x25519, KeyPair mlKem) {}
  public record Offer(byte[] x25519Ephemeral, byte[] mlKemCiphertext) {
    public Offer {
      x25519Ephemeral = x25519Ephemeral == null ? null : x25519Ephemeral.clone();
      mlKemCiphertext = mlKemCiphertext == null ? null : mlKemCiphertext.clone();
    }
    @Override public byte[] x25519Ephemeral() { return x25519Ephemeral == null ? null : x25519Ephemeral.clone(); }
    @Override public byte[] mlKemCiphertext() { return mlKemCiphertext == null ? null : mlKemCiphertext.clone(); }
    public int wireBytes() {
      return (x25519Ephemeral == null ? 0 : x25519Ephemeral.length)
          + (mlKemCiphertext == null ? 0 : mlKemCiphertext.length);
    }
  }
  public record ClientResult(byte[] sharedSecret, Offer offer) implements AutoCloseable {
    public ClientResult { sharedSecret = sharedSecret.clone(); }
    @Override public byte[] sharedSecret() { return sharedSecret.clone(); }
    @Override public void close() { Arrays.fill(sharedSecret, (byte) 0); }
  }

  private HybridKem() {}

  public static ServerKeys generate(Mode mode) throws GeneralSecurityException {
    KeyPair x = mode == Mode.ML_KEM_768 ? null : KeyPairGenerator.getInstance("X25519").generateKeyPair();
    KeyPair ml = mode == Mode.X25519 ? null : KeyPairGenerator.getInstance("ML-KEM-768").generateKeyPair();
    return new ServerKeys(x, ml);
  }

  public static ClientResult encapsulate(Mode mode, PublicKey serverX25519, PublicKey serverMlKem)
      throws GeneralSecurityException {
    byte[] xSecret = null, xEphemeral = null, mlSecret = null, mlCiphertext = null;
    if (mode != Mode.ML_KEM_768) {
      KeyPair ephemeral = KeyPairGenerator.getInstance("X25519").generateKeyPair();
      KeyAgreement agreement = KeyAgreement.getInstance("X25519");
      agreement.init(ephemeral.getPrivate());
      agreement.doPhase(serverX25519, true);
      xSecret = agreement.generateSecret();
      xEphemeral = ephemeral.getPublic().getEncoded();
    }
    if (mode != Mode.X25519) {
      KEM.Encapsulated encapsulated = KEM.getInstance("ML-KEM")
          .newEncapsulator(serverMlKem).encapsulate();
      mlSecret = encapsulated.key().getEncoded();
      mlCiphertext = encapsulated.encapsulation();
    }
    byte[] combined = combine(xSecret, mlSecret);
    try {
      return new ClientResult(combined, new Offer(xEphemeral, mlCiphertext));
    } finally {
      Arrays.fill(combined, (byte) 0);
      if (xSecret != null) Arrays.fill(xSecret, (byte) 0);
      if (mlSecret != null) Arrays.fill(mlSecret, (byte) 0);
    }
  }

  public static PublicKey x25519Public(byte[] encoded) throws GeneralSecurityException {
    return KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(encoded));
  }

  public static PublicKey mlKemPublic(byte[] encoded) throws GeneralSecurityException {
    return KeyFactory.getInstance("ML-KEM").generatePublic(new X509EncodedKeySpec(encoded));
  }

  public static byte[] decapsulate(Mode mode, ServerKeys keys, Offer offer) throws GeneralSecurityException {
    byte[] xSecret = null, mlSecret = null;
    if (mode != Mode.ML_KEM_768) {
      PublicKey peer = x25519Public(offer.x25519Ephemeral());
      KeyAgreement agreement = KeyAgreement.getInstance("X25519");
      agreement.init(keys.x25519().getPrivate());
      agreement.doPhase(peer, true);
      xSecret = agreement.generateSecret();
    }
    if (mode != Mode.X25519) {
      SecretKey secret = KEM.getInstance("ML-KEM").newDecapsulator(keys.mlKem().getPrivate())
          .decapsulate(offer.mlKemCiphertext());
      mlSecret = secret.getEncoded();
    }
    try {
      return combine(xSecret, mlSecret);
    } finally {
      if (xSecret != null) Arrays.fill(xSecret, (byte) 0);
      if (mlSecret != null) Arrays.fill(mlSecret, (byte) 0);
    }
  }

  static byte[] combine(byte[] xSecret, byte[] mlSecret) throws GeneralSecurityException {
    ByteArrayOutputStream data = new ByteArrayOutputStream();
    for (byte[] part : new byte[][] {xSecret, mlSecret}) {
      int length = part == null ? 0 : part.length;
      data.write(length >>> 8);
      data.write(length);
      if (part != null) data.writeBytes(part);
    }
    Mac extract = Mac.getInstance("HmacSHA256");
    extract.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
    byte[] prk = extract.doFinal(data.toByteArray());
    try {
      Mac expand = Mac.getInstance("HmacSHA256");
      expand.init(new SecretKeySpec(prk, "HmacSHA256"));
      expand.update("pqh/hybrid-kem/v1".getBytes(java.nio.charset.StandardCharsets.UTF_8));
      expand.update((byte) 1);
      return expand.doFinal();
    } finally {
      Arrays.fill(prk, (byte) 0);
    }
  }
}
