package pqh.research;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/** ML-DSA-65 signed evidence checkpoints. */
public final class CheckpointSigner {
  private CheckpointSigner() {}

  public record Checkpoint(long epoch, long seq, String chainHash, long timestamp, byte[] signature) {
    public Checkpoint {
      if (epoch < 0 || seq < 1 || chainHash == null || signature == null) {
        throw new IllegalArgumentException("invalid checkpoint");
      }
      signature = signature.clone();
    }

    @Override public byte[] signature() { return signature.clone(); }
  }

  public static KeyPair generate() {
    try {
      return KeyPairGenerator.getInstance("ML-DSA-65").generateKeyPair();
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("ML-DSA-65 is not available on this JDK", ex);
    }
  }

  public static byte[] message(String nodeId, long seq, String chainHash, long timestamp) {
    return message(nodeId, 0, seq, chainHash, timestamp);
  }

  public static byte[] message(String nodeId, long epoch, long seq, String chainHash, long timestamp) {
    return ("pqh/checkpoint/v1\n" + nodeId.length() + ":" + nodeId + "\n" + epoch + "\n"
        + seq + "\n" + chainHash + "\n" + timestamp).getBytes(StandardCharsets.UTF_8);
  }

  public static byte[] sign(PrivateKey key, String nodeId, long seq, String chainHash, long timestamp) {
    return sign(key, nodeId, 0, seq, chainHash, timestamp);
  }

  public static byte[] sign(PrivateKey key, String nodeId, long epoch, long seq,
                            String chainHash, long timestamp) {
    try {
      Signature signature = Signature.getInstance("ML-DSA");
      signature.initSign(key);
      signature.update(message(nodeId, epoch, seq, chainHash, timestamp));
      return signature.sign();
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("checkpoint signing failed", ex);
    }
  }

  public static boolean verify(PublicKey key, String nodeId, long seq, String chainHash,
                               long timestamp, byte[] bytes) {
    return verify(key, nodeId, 0, seq, chainHash, timestamp, bytes);
  }

  public static boolean verify(PublicKey key, String nodeId, long epoch, long seq, String chainHash,
                               long timestamp, byte[] bytes) {
    try {
      Signature signature = Signature.getInstance("ML-DSA");
      signature.initVerify(key);
      signature.update(message(nodeId, epoch, seq, chainHash, timestamp));
      return signature.verify(bytes);
    } catch (GeneralSecurityException | RuntimeException ex) {
      return false;
    }
  }

  public static PrivateKey decodePrivateKey(String encoded) {
    try {
      return KeyFactory.getInstance("ML-DSA")
          .generatePrivate(new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(encoded)));
    } catch (GeneralSecurityException | IllegalArgumentException ex) {
      throw new IllegalArgumentException("invalid ML-DSA private key", ex);
    }
  }

  public static String readKeyMaterial(String encoded, String file, String keyName) {
    boolean inlineConfigured = encoded != null && !encoded.isBlank();
    boolean fileConfigured = file != null && !file.isBlank();
    if (inlineConfigured && fileConfigured) {
      throw new IllegalArgumentException("configure either the inline " + keyName
          + " key or its file, not both");
    }
    if (!fileConfigured) return encoded;
    try {
      return Files.readString(Path.of(file), StandardCharsets.UTF_8).trim();
    } catch (IOException | RuntimeException ex) {
      throw new IllegalStateException("could not read configured ML-DSA " + keyName + " key file", ex);
    }
  }

  public static PublicKey decodePublicKey(String encoded) {
    try {
      return KeyFactory.getInstance("ML-DSA")
          .generatePublic(new X509EncodedKeySpec(java.util.Base64.getDecoder().decode(encoded)));
    } catch (GeneralSecurityException | IllegalArgumentException ex) {
      throw new IllegalArgumentException("invalid ML-DSA public key", ex);
    }
  }

  public static boolean matches(PrivateKey privateKey, PublicKey publicKey) {
    byte[] challenge = "pqh/checkpoint-key-pair-check".getBytes(StandardCharsets.UTF_8);
    byte[] signature = null;
    try {
      Signature signer = Signature.getInstance("ML-DSA");
      signer.initSign(privateKey);
      signer.update(challenge);
      signature = signer.sign();
      Signature verifier = Signature.getInstance("ML-DSA");
      verifier.initVerify(publicKey);
      verifier.update(challenge);
      return verifier.verify(signature);
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("ML-DSA key-pair validation failed", ex);
    } finally {
      Arrays.fill(challenge, (byte) 0);
      if (signature != null) Arrays.fill(signature, (byte) 0);
    }
  }
}
