package pqh.crypto;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.springframework.stereotype.Service;

/** ML-KEM-768 (JDK 24 JEP 496), HKDF-SHA256 (RFC 5869), AES-256-GCM with counter nonces. */
@Service
public class CryptoService {
  public record Encapsulated(byte[] secret, byte[] ciphertext) {}

  public KeyPair kemKeyPair() throws GeneralSecurityException { return KeyPairGenerator.getInstance("ML-KEM-768").generateKeyPair(); }
  public PublicKey kemPublic(byte[] enc) throws GeneralSecurityException { return KeyFactory.getInstance("ML-KEM").generatePublic(new X509EncodedKeySpec(enc)); }
  public Encapsulated encapsulate(PublicKey pk) throws GeneralSecurityException {
    var r = KEM.getInstance("ML-KEM").newEncapsulator(pk).encapsulate();
    return new Encapsulated(r.key().getEncoded(), r.encapsulation());
  }
  public byte[] decapsulate(PrivateKey sk, byte[] ct) throws GeneralSecurityException {
    return KEM.getInstance("ML-KEM").newDecapsulator(sk).decapsulate(ct).getEncoded();
  }
  public byte[] hmac(byte[] key, byte[]... parts) throws GeneralSecurityException {
    Mac m = Mac.getInstance("HmacSHA256"); m.init(new SecretKeySpec(key.length == 0 ? new byte[32] : key, "HmacSHA256"));
    for (byte[] p : parts) m.update(p); return m.doFinal();
  }
  public byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int len) throws GeneralSecurityException {
    byte[] prk = hmac(salt, ikm), out = new byte[len], t = new byte[0];
    for (int i = 1, pos = 0; pos < len; i++) {
      t = hmac(prk, t, info, new byte[]{(byte) i});
      int n = Math.min(t.length, len - pos); System.arraycopy(t, 0, out, pos, n); pos += n;
    }
    return out;
  }
  /** nonce = 4-byte session salt || 8-byte counter (never random, never reused). */
  public byte[] nonce(byte[] salt4, long counter) { return ByteBuffer.allocate(12).put(salt4).putLong(counter).array(); }
  public byte[] seal(byte[] key, byte[] nonce, byte[] aad, byte[] pt) throws GeneralSecurityException { return gcm(Cipher.ENCRYPT_MODE, key, nonce, aad, pt); }
  public byte[] open(byte[] key, byte[] nonce, byte[] aad, byte[] ct) throws GeneralSecurityException { return gcm(Cipher.DECRYPT_MODE, key, nonce, aad, ct); }
  private byte[] gcm(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] in) throws GeneralSecurityException {
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce)); c.updateAAD(aad); return c.doFinal(in);
  }
}
