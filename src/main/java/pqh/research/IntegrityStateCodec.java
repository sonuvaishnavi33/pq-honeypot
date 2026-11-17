package pqh.research;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Versioned AES-GCM persistence format for the optional bootstrap seed and current ratchet state. */
public final class IntegrityStateCodec {
  private static final int VERSION = 1;
  private static final int NONCE_BYTES = 12;

  private IntegrityStateCodec() {}

  public record State(byte[] streamSeed, ForwardSecureSeal.State ratchetState) {
    public State {
      if (streamSeed == null || (streamSeed.length > 0 && streamSeed.length < 16)
          || ratchetState == null) {
        throw new IllegalArgumentException("invalid integrity state");
      }
      streamSeed = streamSeed.clone();
    }

    @Override public byte[] streamSeed() { return streamSeed.clone(); }
  }

  public static byte[] encode(State state) {
    try {
      ByteArrayOutputStream bytes = new ByteArrayOutputStream();
      DataOutputStream output = new DataOutputStream(bytes);
      byte[] seed = state.streamSeed();
      byte[] key = state.ratchetState().key();
      byte[] previousTag = state.ratchetState().previousTag();
      if (key.length != 32 || previousTag.length != 32 || state.ratchetState().epoch() < 0) {
        throw new IllegalArgumentException("invalid ratchet state");
      }
      output.writeInt(VERSION);
      output.writeInt(seed.length);
      output.write(seed);
      output.writeLong(state.ratchetState().epoch());
      output.writeInt(key.length);
      output.write(key);
      output.writeInt(previousTag.length);
      output.write(previousTag);
      output.flush();
      return bytes.toByteArray();
    } catch (IOException ex) {
      throw new IllegalStateException("could not encode integrity state", ex);
    }
  }

  public static State decode(byte[] encoded) {
    try {
      DataInputStream input = new DataInputStream(new ByteArrayInputStream(encoded));
      if (input.readInt() != VERSION) throw new IllegalArgumentException("unsupported integrity-state version");
      byte[] seed = readBounded(input, 0, 128);
      long epoch = input.readLong();
      byte[] key = readBounded(input, 32, 32);
      byte[] previousTag = readBounded(input, 32, 32);
      if (epoch < 0 || input.available() != 0) throw new IllegalArgumentException("invalid integrity-state payload");
      return new State(seed, new ForwardSecureSeal.State(key, epoch, previousTag));
    } catch (IOException ex) {
      throw new IllegalArgumentException("invalid integrity-state payload", ex);
    }
  }

  public static byte[] encrypt(byte[] key, byte[] plaintext, byte[] aad) throws GeneralSecurityException {
    if (key.length != 32) throw new IllegalArgumentException("AES-256 key required");
    byte[] nonce = new byte[NONCE_BYTES];
    new SecureRandom().nextBytes(nonce);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
    cipher.updateAAD(aad);
    byte[] ciphertext = cipher.doFinal(plaintext);
    byte[] result = Arrays.copyOf(nonce, nonce.length + ciphertext.length);
    System.arraycopy(ciphertext, 0, result, nonce.length, ciphertext.length);
    return result;
  }

  public static byte[] decrypt(byte[] key, byte[] encrypted, byte[] aad) throws GeneralSecurityException {
    if (key.length != 32 || encrypted.length <= NONCE_BYTES + 16) {
      throw new IllegalArgumentException("invalid encrypted integrity state");
    }
    byte[] nonce = Arrays.copyOf(encrypted, NONCE_BYTES);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
    cipher.updateAAD(aad);
    return cipher.doFinal(encrypted, NONCE_BYTES, encrypted.length - NONCE_BYTES);
  }

  private static byte[] readBounded(DataInputStream input, int min, int max) throws IOException {
    int length = input.readInt();
    if (length < min || length > max) throw new IllegalArgumentException("invalid integrity-state field length");
    byte[] bytes = input.readNBytes(length);
    if (bytes.length != length) throw new IllegalArgumentException("truncated integrity-state payload");
    return bytes;
  }
}
