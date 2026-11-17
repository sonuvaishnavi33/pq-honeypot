package pqh;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import pqh.crypto.*;

class CryptoTest {
  final CryptoService c = new CryptoService();
  @Test void kemAgrees() throws Exception { var kp = c.kemKeyPair(); var e = c.encapsulate(kp.getPublic()); assertArrayEquals(e.secret(), c.decapsulate(kp.getPrivate(), e.ciphertext())); }
  @Test void tamperRejected() throws Exception {
    byte[] k = new byte[32], n = c.nonce(new byte[4], 1), a = {1}; byte[] ct = c.seal(k, n, a, "x".getBytes(StandardCharsets.UTF_8)); ct[0] ^= 1;
    assertThrows(Exception.class, () -> c.open(k, n, a, ct));
  }
  @Test void chainDetectsEdit() {
    String h1 = HashChain.next("g", 1, "a"), h2 = HashChain.next(h1, 2, "b");
    assertEquals(-1, HashChain.verify("g", 1, java.util.List.of(new HashChain.Link(1, "a", h1), new HashChain.Link(2, "b", h2))));
    assertEquals(1, HashChain.verify("g", 1, java.util.List.of(new HashChain.Link(1, "a", h1), new HashChain.Link(2, "X", h2))));
  }
}
