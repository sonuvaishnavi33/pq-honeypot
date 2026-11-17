package pqh.honeypot;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import pqh.crypto.*;
import pqh.research.CheckpointSigner;
import pqh.research.ForwardSecureSeal;
import pqh.research.HybridKem;
import pqh.research.KemProperties;

/** Negotiates the configured KEM, then ships authenticated encrypted evidence batches. */
@Service @Profile("honeypot")
public class ForwardService {
  private final CryptoService c; private final EventService events; private final EpochIntegrityService integrity; private final ObjectMapper om;
  private final RestClient http; private final String node, psk; private final int batch, maxBatches;
  private final KemProperties kem;
  private String sessionId; private byte[] key, salt; private long counter; private int sent;
  private long collectorLastSealedSeq;
  private long collectorLastCheckpointSeq;
  private volatile String lastStatus = "NO_TRANSFER_YET";

  public ForwardService(CryptoService c, EventService e, EpochIntegrityService integrity, ObjectMapper om,
      @Value("${app.collector-url}") String url, @Value("${app.node-id}") String node,
      @Value("${app.psk}") String psk, @Value("${app.batch-size}") int batch,
      @Value("${app.session-max-batches}") int maxBatches, KemProperties kem) {
    this.c = c; this.events = e; this.integrity = integrity; this.om = om; this.node = node;
    this.psk = psk; this.batch = batch; this.maxBatches = maxBatches; this.kem = kem;
    this.http = RestClient.create(url);
  }
  public String lastStatus() { return lastStatus; }
  public RestClient client() { return http; }

  public synchronized void resetSession() {
    if (key != null) Arrays.fill(key, (byte) 0);
    if (salt != null) Arrays.fill(salt, (byte) 0);
    sessionId = null;
    key = null;
    salt = null;
    counter = 0;
    sent = 0;
    collectorLastSealedSeq = 0;
    collectorLastCheckpointSeq = 0;
    lastStatus = "NO_TRANSFER_YET";
  }

  @Scheduled(fixedDelayString = "${app.forward-interval-ms}")
  public void scheduled() { try { forward(); } catch (Exception ex) { lastStatus = "ERROR: " + ex.getMessage(); } }

  public synchronized String forward() throws Exception {
    try {
      var recs = events.pending(batch);
      if (recs.isEmpty()) return lastStatus = "NOTHING_PENDING";
      if (key == null || sent >= maxBatches) handshake();
      long first = recs.get(0).ev().seq(), last = recs.get(recs.size() - 1).ev().seq();
      byte[] aad = (sessionId + "|" + node + "|" + first + "|" + last).getBytes(StandardCharsets.UTF_8);
      byte[] nonce = c.nonce(salt, counter++);
      List<ForwardSecureSeal.Epoch> seals = integrity.sealsAfter(collectorLastSealedSeq, last);
      List<CheckpointSigner.Checkpoint> checkpoints =
          integrity.checkpointsAfter(collectorLastCheckpointSeq, last);
      byte[] ct = c.seal(key, nonce, aad, om.writeValueAsBytes(new EvidenceBatch(recs, seals, checkpoints)));
      Map<?, ?> resp = http.post().uri("/api/evidence").body(Map.of("sessionId", sessionId, "nodeId", node, "firstSeq", first, "lastSeq", last,
          "nonce", b64(nonce), "ciphertext", b64(ct))).retrieve().body(Map.class);
      sent++;
      String status = String.valueOf(resp.get("status"));
      if ("OK".equals(status)) {
        events.markSent(first, last);
        if (!seals.isEmpty()) collectorLastSealedSeq = seals.get(seals.size() - 1).lastSeq();
        if (!checkpoints.isEmpty()) {
          collectorLastCheckpointSeq = checkpoints.get(checkpoints.size() - 1).seq();
        }
      }
      return lastStatus = status + " (seq " + first + "-" + last + ")";
    } catch (Exception ex) {
      lastStatus = "ERROR: " + ex.getMessage();
      throw ex;
    }
  }
  private void handshake() throws Exception {
    byte[] nonceH = new byte[16]; new SecureRandom().nextBytes(nonceH);
    long ts = System.currentTimeMillis(); byte[] k = psk.getBytes(StandardCharsets.UTF_8);
    byte[] streamSeed = new byte[0], bootstrapKey = null, sharedSecret = null;
    try {
      Map<?, ?> r1 = http.post().uri("/api/handshake/init").body(Map.of("nodeId", node,
          "nonceH", b64(nonceH), "ts", ts,
          "mac", b64(c.hmac(k, (node + "|" + b64(nonceH) + "|" + ts)
              .getBytes(StandardCharsets.UTF_8))))).retrieve().body(Map.class);
      String sid = (String) r1.get("sessionId");
      byte[] nonceC = unb64((String) r1.get("nonceC"));
      long reportedLastSealedSeq = ((Number) r1.get("lastSealedSeq")).longValue();
      long reportedLastCheckpointSeq = ((Number) r1.get("lastCheckpointSeq")).longValue();
      String publicKeyMacInput = sid + "|" + r1.get("x25519PublicKey") + "|"
          + r1.get("mlKemPublicKey") + "|" + r1.get("nonceC") + "|" + reportedLastSealedSeq
          + "|" + reportedLastCheckpointSeq;
      byte[] expect = c.hmac(k, publicKeyMacInput.getBytes(StandardCharsets.UTF_8));
      if (!java.security.MessageDigest.isEqual(expect, unb64((String) r1.get("mac")))) {
        throw new SecurityException("Collector authentication failed");
      }
      if (!kem.mode().name().equals(r1.get("kemMode"))) {
        throw new SecurityException("Configured KEM mode does not match collector");
      }
      byte[] xPublic = r1.get("x25519PublicKey") == null
          ? null : unb64((String) r1.get("x25519PublicKey"));
      byte[] mlPublic = r1.get("mlKemPublicKey") == null
          ? null : unb64((String) r1.get("mlKemPublicKey"));
      HybridKem.ClientResult enc = HybridKem.encapsulate(kem.mode(),
          xPublic == null ? null : HybridKem.x25519Public(xPublic),
          mlPublic == null ? null : HybridKem.mlKemPublic(mlPublic));
      sharedSecret = enc.sharedSecret();
      enc.close();
      Map<String, Object> finish = new HashMap<>();
      finish.put("sessionId", sid);
      finish.put("kemMode", kem.mode().name());
      if (enc.offer().x25519Ephemeral() != null) {
        finish.put("x25519Ephemeral", b64(enc.offer().x25519Ephemeral()));
      }
      if (enc.offer().mlKemCiphertext() != null) {
        finish.put("mlKemCiphertext", b64(enc.offer().mlKemCiphertext()));
      }
      streamSeed = integrity.streamSeed();
      if (streamSeed.length > 0) {
        byte[] context = ("pqh/ratchet-bootstrap|" + sid + "|" + node).getBytes(StandardCharsets.UTF_8);
        bootstrapKey = c.hkdf(sharedSecret, nonceH, context, 32);
        byte[] bootstrapAad = ("ratchet-bootstrap|" + sid + "|" + node)
            .getBytes(StandardCharsets.UTF_8);
        byte[] bootstrapNonce = c.nonce(new byte[4], 0);
        finish.put("ratchetSeed", b64(c.seal(bootstrapKey, bootstrapNonce, bootstrapAad, streamSeed)));
      }
      http.post().uri("/api/handshake/finish").body(finish).retrieve().toBodilessEntity();
      integrity.markSeedBootstrapped();
      byte[] newKey = c.hkdf(sharedSecret, concat(nonceH, nonceC),
          ("enc|" + sid + "|" + node).getBytes(StandardCharsets.UTF_8), 32);
      byte[] newSalt = Arrays.copyOf(c.hkdf(sharedSecret, nonceH,
          "salt".getBytes(StandardCharsets.UTF_8), 4), 4);
      key = newKey;
      salt = newSalt;
      sessionId = sid;
      collectorLastSealedSeq = reportedLastSealedSeq;
      collectorLastCheckpointSeq = reportedLastCheckpointSeq;
      counter = 0;
      sent = 0;
    } finally {
      Arrays.fill(k, (byte) 0);
      Arrays.fill(streamSeed, (byte) 0);
      if (bootstrapKey != null) Arrays.fill(bootstrapKey, (byte) 0);
      if (sharedSecret != null) Arrays.fill(sharedSecret, (byte) 0);
    }
  }
  static byte[] concat(byte[] a, byte[] b) { byte[] o = Arrays.copyOf(a, a.length + b.length); System.arraycopy(b, 0, o, a.length, b.length); return o; }
  static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
  static byte[] unb64(String s) { return Base64.getDecoder().decode(s); }
}
