package pqh.collector;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.AEADBadTagException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import pqh.crypto.*;
import pqh.research.ForwardSecureSeal;
import pqh.research.HybridKem;
import pqh.research.CheckpointSigner;
import pqh.research.IntegrityMode;
import pqh.research.IntegrityProperties;
import pqh.research.IntegrityStateCodec;
import pqh.research.KemProperties;

/** Remote forensic collector: authenticates handshake, decapsulates, verifies, stores. */
@RestController @RequestMapping("/api") @Profile("collector")
public class CollectorController {
  private record Session(String node, HybridKem.ServerKeys kem, byte[] nonceH, byte[] nonceC,
                         byte[] key, byte[] salt, long lastCounter) {}
  private record Ratchet(IntegrityStateCodec.State state, ForwardSecureSeal.Verifier verifier,
                         long lastSealedSeq) implements AutoCloseable {
    @Override public void close() { verifier.close(); }
  }
  private final Map<String, Session> sessions = new ConcurrentHashMap<>();
  private final CryptoService c; private final JdbcTemplate db; private final ObjectMapper om; private final byte[] psk;
  private final long maxAgeMs; private final boolean demo; private final IntegrityProperties integrity;
  private final KemProperties kem;
  private final PublicKey checkpointPublicKey;

  public CollectorController(CryptoService c, JdbcTemplate db, ObjectMapper om, @Value("${app.psk}") String psk,
      @Value("${app.handshake-max-age-sec}") int maxAge, @Value("${app.demo-mode}") boolean demo,
      IntegrityProperties integrity, KemProperties kem) {
    this.c = c; this.db = db; this.om = om; this.psk = psk.getBytes(StandardCharsets.UTF_8);
    this.maxAgeMs = maxAge * 1000L; this.demo = demo; this.integrity = integrity; this.kem = kem;
    if (integrity.mode().anchor) {
      String publicMaterial = CheckpointSigner.readKeyMaterial(integrity.checkpointPublicKey(),
          integrity.checkpointPublicKeyFile(), "public");
      if (publicMaterial == null || publicMaterial.isBlank()) {
        throw new IllegalStateException("checkpoint mode requires checkpoint public key material");
      }
      this.checkpointPublicKey = CheckpointSigner.decodePublicKey(publicMaterial);
    } else {
      this.checkpointPublicKey = null;
    }
  }
  private String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
  private byte[] unb64(Object s) { return Base64.getDecoder().decode((String) s); }

  @PostMapping("/handshake/init")
  public Map<String, Object> init(@RequestBody Map<String, Object> m) throws Exception {
    String node = (String) m.get("nodeId"), nh = (String) m.get("nonceH"); long ts = ((Number) m.get("ts")).longValue();
    byte[] expect = c.hmac(psk, (node + "|" + nh + "|" + ts).getBytes(StandardCharsets.UTF_8));
    if (Math.abs(System.currentTimeMillis() - ts) > maxAgeMs || !MessageDigest.isEqual(expect, unb64(m.get("mac")))) { audit(node, "AUTH_FAIL", "bad hello"); throw new SecurityException("auth"); }
    HybridKem.ServerKeys keys = HybridKem.generate(kem.mode());
    byte[] nc = new byte[16]; new SecureRandom().nextBytes(nc);
    String sid = UUID.randomUUID().toString().replace("-", "");
    String xPublic = keys.x25519() == null ? null : b64(keys.x25519().getPublic().getEncoded());
    String mlPublic = keys.mlKem() == null ? null : b64(keys.mlKem().getPublic().getEncoded());
    sessions.put(sid, new Session(node, keys, unb64(nh), nc, null, null, -1));
    long lastSealedSeq = integrity.mode().ratchet
        ? db.query("SELECT last_sealed_seq FROM collector_integrity_state WHERE node_id=?",
            rs -> rs.next() ? rs.getLong(1) : 0L, node)
        : 0L;
    long lastCheckpointSeq = integrity.mode().anchor
        ? db.query("SELECT COALESCE(MAX(seq_no),0) FROM collector_integrity_checkpoint WHERE node_id=?",
            rs -> rs.next() ? rs.getLong(1) : 0L, node)
        : 0L;
    Map<String, Object> response = new HashMap<>();
    response.put("sessionId", sid);
    response.put("kemMode", kem.mode().name());
    response.put("x25519PublicKey", xPublic);
    response.put("mlKemPublicKey", mlPublic);
    response.put("nonceC", b64(nc));
    response.put("lastSealedSeq", lastSealedSeq);
    response.put("lastCheckpointSeq", lastCheckpointSeq);
    String macInput = sid + "|" + xPublic + "|" + mlPublic + "|" + b64(nc) + "|"
        + lastSealedSeq + "|" + lastCheckpointSeq;
    response.put("mac", b64(c.hmac(psk, macInput.getBytes(StandardCharsets.UTF_8))));
    return response;
  }
  @PostMapping("/handshake/finish")
  public Map<String, String> finish(@RequestBody Map<String, Object> m) throws Exception {
    String sid = (String) m.get("sessionId"); Session s = sessions.get(sid); if (s == null) throw new SecurityException("no session");
    if (!kem.mode().name().equals(m.get("kemMode"))) throw new SecurityException("KEM mode mismatch");
    HybridKem.Offer offer = new HybridKem.Offer(
        m.get("x25519Ephemeral") == null ? null : unb64(m.get("x25519Ephemeral")),
        m.get("mlKemCiphertext") == null ? null : unb64(m.get("mlKemCiphertext")));
    byte[] ss = HybridKem.decapsulate(kem.mode(), s.kem(), offer);
    try {
      byte[] key = c.hkdf(ss, ForwardConcat.concat(s.nonceH(), s.nonceC()),
          ("enc|" + sid + "|" + s.node()).getBytes(StandardCharsets.UTF_8), 32);
      byte[] salt = Arrays.copyOf(c.hkdf(ss, s.nonceH(), "salt".getBytes(StandardCharsets.UTF_8), 4), 4);
      if (integrity.mode().ratchet) initializeRatchet(s, sid, m, ss);
      sessions.put(sid, new Session(s.node(), null, s.nonceH(), s.nonceC(), key, salt, -1));
    } finally {
      Arrays.fill(ss, (byte) 0);
    }
    return Map.of("status", "OK");
  }
  @PostMapping("/evidence")
  @Transactional
  public synchronized Map<String, Object> evidence(@RequestBody Map<String, Object> m) throws Exception {
    String sid = (String) m.get("sessionId"), node = (String) m.get("nodeId"); long first = ((Number) m.get("firstSeq")).longValue(), last = ((Number) m.get("lastSeq")).longValue();
    Session s = sessions.get(sid); if (s == null || s.key() == null || !s.node().equals(node)) return audit(node, "NO_SESSION", "unknown session");
    byte[] nonce = unb64(m.get("nonce")); long ctr = java.nio.ByteBuffer.wrap(nonce, 4, 8).getLong();
    if (ctr <= s.lastCounter() || !Arrays.equals(Arrays.copyOf(nonce, 4), s.salt())) return audit(node, "REPLAY", "nonce counter " + ctr);
    byte[] pt;
    try { pt = c.open(s.key(), nonce, (sid + "|" + node + "|" + first + "|" + last).getBytes(StandardCharsets.UTF_8), unb64(m.get("ciphertext"))); }
    catch (AEADBadTagException e) { return audit(node, "TAMPERED", "GCM tag mismatch"); }
    sessions.put(sid, new Session(s.node(), null, s.nonceH(), s.nonceC(), s.key(), s.salt(), ctr));
    EvidenceBatch batch;
    try {
      batch = om.readValue(pt, EvidenceBatch.class);
    } catch (Exception ex) {
      return audit(node, "INVALID_BATCH", ex.getMessage());
    }
    List<Ev.Rec> recs = batch.records();
    if (recs.isEmpty() || recs.get(0).ev().seq() != first
        || recs.get(recs.size() - 1).ev().seq() != last || last < first) {
      return audit(node, "INVALID_RANGE", "payload sequence range does not match request");
    }
    for (int i = 0; i < recs.size(); i++) {
      if (recs.get(i).ev().seq() != first + i) return audit(node, "GAP", "non-contiguous batch sequence");
    }
    Long lastSeq = db.queryForObject("SELECT COALESCE(MAX(seq_no),0) FROM evidence_record WHERE node_id=?", Long.class, node);
    if (first != lastSeq + 1) return audit(node, "GAP", "expected " + (lastSeq + 1) + " got " + first);
    if (integrity.mode().chain) {
      String prev = lastSeq == 0 ? HashChain.genesis(node) : db.queryForObject(
          "SELECT chain_hash FROM evidence_record WHERE node_id=? AND seq_no=?", String.class, node, lastSeq);
      int bad = HashChain.verify(prev, first,
          recs.stream().map(r -> new HashChain.Link(r.ev().seq(), r.ev().canonical(), r.hash())).toList());
      if (bad >= 0) return audit(node, "CHAIN_BROKEN", "first bad link index " + bad);
    }
    Ratchet ratchet = integrity.mode().ratchet ? loadRatchet(node) : null;
    try {
      if (integrity.mode().ratchet && ratchet == null) {
        return audit(node, "NO_RATCHET_STATE", "authenticated handshake state is missing");
      }
      long verifiedThrough = ratchet == null ? 0 : verifySeals(node, batch.seals(), recs, first, last,
          ratchet.lastSealedSeq(), ratchet.verifier());
      if (ratchet != null && verifiedThrough < 0) {
        return audit(node, "BAD_SEAL", "epoch, range, head, or tag verification failed");
      }
      if (integrity.mode().anchor && !verifyCheckpoints(node, batch.checkpoints(), recs, first, last)) {
        return audit(node, "BAD_CHECKPOINT", "checkpoint signature, epoch, range, or chain head invalid");
      }
      for (Ev.Rec r : recs) {
        db.update("INSERT INTO evidence_record(node_id,seq_no,event_json,chain_hash) VALUES(?,?,?,?)",
            node, r.ev().seq(), om.writeValueAsString(r.ev()), r.hash());
      }
      if (ratchet != null && verifiedThrough > ratchet.lastSealedSeq()) {
        persistRatchet(node, new IntegrityStateCodec.State(ratchet.state().streamSeed(),
            ratchet.verifier().exportState()), verifiedThrough);
        for (ForwardSecureSeal.Epoch seal : batch.seals()) {
          if (seal.lastSeq() <= verifiedThrough) {
            db.update("INSERT INTO collector_integrity_epoch(node_id,epoch_no,first_seq,last_seq,chain_head,seal_tag) "
                    + "VALUES(?,?,?,?,?,?)",
                node, seal.epoch(), seal.firstSeq(), seal.lastSeq(), seal.chainHead(), seal.tag());
          }
        }
      }
      if (integrity.mode().anchor) {
        for (CheckpointSigner.Checkpoint checkpoint : batch.checkpoints()) {
          db.update("INSERT INTO collector_integrity_checkpoint(node_id,epoch_no,seq_no,chain_hash,"
                  + "checkpoint_timestamp,signature) VALUES(?,?,?,?,?,?)",
              node, checkpoint.epoch(), checkpoint.seq(), checkpoint.chainHash(),
              checkpoint.timestamp(), checkpoint.signature());
        }
      }
    } finally {
      if (ratchet != null) ratchet.close();
    }
    audit(node, "OK", "stored " + first + "-" + last);
    return Map.of("status", "OK", "lastAcceptedSeq", last);
  }
  @GetMapping("/stats")
  public Map<String, Object> stats() {
    return Map.of("records", db.queryForObject("SELECT COUNT(*) FROM evidence_record", Long.class), "audit", db.queryForList("SELECT at,node_id,result,detail FROM audit_log ORDER BY id DESC LIMIT 15"));
  }
  @GetMapping("/verify")
  public Map<String, Object> verifyStored() throws Exception {
    if (!integrity.mode().chain) return Map.of("status", "NOT_APPLICABLE", "mode", integrity.mode().name());
    List<String> nodes = db.queryForList("SELECT DISTINCT node_id FROM evidence_record", String.class);
    Map<String, String> nodeStatus = new LinkedHashMap<>();
    for (String node : nodes) nodeStatus.put(node, verifyStoredNode(node));
    boolean valid = nodeStatus.values().stream().allMatch("OK"::equals);
    boolean incomplete = nodeStatus.values().stream().allMatch(status ->
        "OK".equals(status) || "UNSEALED_TAIL".equals(status) || "UNANCHORED_TAIL".equals(status));
    String status = valid ? "OK" : incomplete ? "INCOMPLETE" : "INTEGRITY_FAILURE";
    return Map.of("status", status, "nodes", nodeStatus);
  }
  @PostMapping("/reset")
  public ResponseEntity<String> reset() {
    if (!demo) return ResponseEntity.status(403).body("demo-mode off");
    db.update("DELETE FROM evidence_record");
    db.update("DELETE FROM audit_log");
    db.update("DELETE FROM collector_integrity_epoch");
    db.update("DELETE FROM collector_integrity_state");
    db.update("DELETE FROM collector_integrity_checkpoint");
    sessions.clear();
    return ResponseEntity.ok("reset");
  }

  private void initializeRatchet(Session session, String sid, Map<String, Object> message,
                                 byte[] sharedSecret) throws Exception {
    Object encryptedSeed = message.get("ratchetSeed");
    byte[] existing = db.query("SELECT encrypted_state FROM collector_integrity_state WHERE node_id=?",
        rs -> rs.next() ? rs.getBytes(1) : null, session.node());
    if (existing != null) {
      try (Ratchet ignored = loadRatchet(session.node())) {
        return;
      }
    }
    if (!(encryptedSeed instanceof String encoded) || encoded.isBlank()) {
      throw new SecurityException("ratchet seed bootstrap is required for an uninitialized collector");
    }
    byte[] bootstrapKey = c.hkdf(sharedSecret, session.nonceH(),
        ("pqh/ratchet-bootstrap|" + sid + "|" + session.node()).getBytes(StandardCharsets.UTF_8), 32);
    byte[] seed = null;
    try {
      seed = c.open(bootstrapKey, c.nonce(new byte[4], 0),
          ("ratchet-bootstrap|" + sid + "|" + session.node()).getBytes(StandardCharsets.UTF_8),
          Base64.getDecoder().decode(encoded));
      if (seed.length < 16) throw new SecurityException("ratchet seed is too short");
      byte[] plaintext;
      try (ForwardSecureSeal.Verifier verifier = new ForwardSecureSeal.Verifier(seed)) {
        plaintext = IntegrityStateCodec.encode(
            new IntegrityStateCodec.State(seed, verifier.exportState()));
      }
      byte[] encrypted = encryptRatchetState(session.node(), plaintext);
      db.update("INSERT IGNORE INTO collector_integrity_state(node_id,encrypted_state,last_sealed_seq) "
              + "VALUES(?,?,0)", session.node(), encrypted);
      Arrays.fill(plaintext, (byte) 0);
    } finally {
      Arrays.fill(bootstrapKey, (byte) 0);
      if (seed != null) Arrays.fill(seed, (byte) 0);
    }
  }

  private Ratchet loadRatchet(String node) {
    byte[] encrypted = db.query("SELECT encrypted_state FROM collector_integrity_state WHERE node_id=?",
        rs -> rs.next() ? rs.getBytes(1) : null, node);
    if (encrypted == null) return null;
    try {
      byte[] encryptionKey = ratchetEncryptionKey(node);
      byte[] plaintext;
      try {
        plaintext = IntegrityStateCodec.decrypt(encryptionKey, encrypted, ratchetAad(node));
      } finally {
        Arrays.fill(encryptionKey, (byte) 0);
      }
      IntegrityStateCodec.State state = IntegrityStateCodec.decode(plaintext);
      Arrays.fill(plaintext, (byte) 0);
      long lastSealed = db.queryForObject(
          "SELECT last_sealed_seq FROM collector_integrity_state WHERE node_id=?", Long.class, node);
      return new Ratchet(state, new ForwardSecureSeal.Verifier(state.ratchetState()), lastSealed);
    } catch (GeneralSecurityException | IllegalArgumentException ex) {
      throw new IllegalStateException("stored collector ratchet state could not be authenticated", ex);
    }
  }

  long verifySeals(String node, List<ForwardSecureSeal.Epoch> seals, List<Ev.Rec> records,
                   long first, long last, long lastSealed, ForwardSecureSeal.Verifier verifier) {
    long verifiedThrough = lastSealed;
    for (ForwardSecureSeal.Epoch seal : seals) {
      if (seal.firstSeq() != verifiedThrough + 1 || seal.lastSeq() > last
          || seal.lastSeq() < seal.firstSeq()) {
        return -1;
      }
      String chainHead;
      if (seal.lastSeq() < first) {
        chainHead = db.query("SELECT chain_hash FROM evidence_record WHERE node_id=? AND seq_no=?",
            rs -> rs.next() ? rs.getString(1) : null, node, seal.lastSeq());
        if (chainHead == null) return -1;
      } else {
        int index = Math.toIntExact(seal.lastSeq() - first);
        if (index >= records.size()) return -1;
        chainHead = records.get(index).hash();
      }
      if (!Objects.equals(chainHead, seal.chainHead())) return -1;
      if (verifier.verify(node, seal) != ForwardSecureSeal.Result.OK) return -1;
      verifiedThrough = seal.lastSeq();
    }
    return verifiedThrough;
  }

  boolean verifyCheckpoints(String node, List<CheckpointSigner.Checkpoint> checkpoints,
                            List<Ev.Rec> records, long first, long last) {
    Long lastEpoch = db.queryForObject(
        "SELECT COALESCE(MAX(epoch_no),-1) FROM collector_integrity_checkpoint WHERE node_id=?",
        Long.class, node);
    long expectedEpoch = (lastEpoch == null ? -1 : lastEpoch) + integrity.checkpointEveryEpochs();
    for (CheckpointSigner.Checkpoint checkpoint : checkpoints) {
      if (checkpoint.epoch() != expectedEpoch || checkpoint.seq() > last
          || (checkpoint.epoch() + 1) % integrity.checkpointEveryEpochs() != 0) return false;
      String chainHash;
      if (checkpoint.seq() < first) {
        chainHash = db.query("SELECT chain_hash FROM evidence_record WHERE node_id=? AND seq_no=?",
            rs -> rs.next() ? rs.getString(1) : null, node, checkpoint.seq());
        if (chainHash == null) return false;
      } else {
        int index = Math.toIntExact(checkpoint.seq() - first);
        if (index >= records.size()) return false;
        chainHash = records.get(index).hash();
      }
      if (!Objects.equals(chainHash, checkpoint.chainHash())
          || !CheckpointSigner.verify(checkpointPublicKey, node, checkpoint.epoch(),
              checkpoint.seq(), checkpoint.chainHash(), checkpoint.timestamp(), checkpoint.signature())) {
        return false;
      }
      expectedEpoch += integrity.checkpointEveryEpochs();
    }
    return true;
  }

  private String verifyStoredNode(String node) throws Exception {
    List<Ev.Rec> records = db.query("SELECT event_json,chain_hash FROM evidence_record "
            + "WHERE node_id=? ORDER BY seq_no",
        (rs, row) -> {
          try {
            return new Ev.Rec(om.readValue(rs.getString("event_json"), Ev.class),
                rs.getString("chain_hash"));
          } catch (com.fasterxml.jackson.core.JsonProcessingException ex) {
            throw new java.sql.SQLException("stored event JSON is invalid", ex);
          }
        }, node);
    List<HashChain.Link> links = records.stream()
        .map(r -> new HashChain.Link(r.ev().seq(), r.ev().canonical(), r.hash())).toList();
    if (HashChain.verify(HashChain.genesis(node), 1, links) >= 0) return "CHAIN_BROKEN";
    Map<Long, String> hashes = new HashMap<>();
    for (Ev.Rec record : records) hashes.put(record.ev().seq(), record.hash());
    String anchorStatus = "OK";
    if (integrity.mode().anchor) {
      List<CheckpointSigner.Checkpoint> checkpoints = db.query(
          "SELECT epoch_no,seq_no,chain_hash,checkpoint_timestamp,signature "
              + "FROM collector_integrity_checkpoint WHERE node_id=? ORDER BY epoch_no",
          (rs, row) -> new CheckpointSigner.Checkpoint(rs.getLong("epoch_no"), rs.getLong("seq_no"),
              rs.getString("chain_hash"), rs.getLong("checkpoint_timestamp"),
              rs.getBytes("signature")), node);
      long expectedEpoch = integrity.checkpointEveryEpochs() - 1L;
      for (CheckpointSigner.Checkpoint checkpoint : checkpoints) {
        if (checkpoint.epoch() != expectedEpoch
            || !Objects.equals(hashes.get(checkpoint.seq()), checkpoint.chainHash())
            || !CheckpointSigner.verify(checkpointPublicKey, node, checkpoint.epoch(),
                checkpoint.seq(), checkpoint.chainHash(), checkpoint.timestamp(), checkpoint.signature())) {
          return "BAD_CHECKPOINT";
        }
        expectedEpoch += integrity.checkpointEveryEpochs();
      }
      long latestStoredSequence = hashes.keySet().stream().mapToLong(Long::longValue).max().orElse(0);
      long latestCheckpointSequence = checkpoints.isEmpty() ? 0
          : checkpoints.get(checkpoints.size() - 1).seq();
      if (latestStoredSequence > latestCheckpointSequence) anchorStatus = "UNANCHORED_TAIL";
    }
    if (integrity.mode().ratchet) {
      String ratchetStatus = verifyStoredRatchet(node, hashes);
      if (!"OK".equals(ratchetStatus)) return ratchetStatus;
    }
    return anchorStatus;
  }

  private String verifyStoredRatchet(String node, Map<Long, String> hashes) {
    try (Ratchet stored = loadRatchet(node)) {
      if (stored == null || stored.state().streamSeed().length < 16) return "NO_RATCHET_STATE";
      long latestStoredSequence = hashes.keySet().stream().mapToLong(Long::longValue).max().orElse(0);
      if (latestStoredSequence > stored.lastSealedSeq()) return "UNSEALED_TAIL";
      try (ForwardSecureSeal.Verifier replay = new ForwardSecureSeal.Verifier(
          stored.state().streamSeed())) {
        List<ForwardSecureSeal.Epoch> epochs = db.query(
            "SELECT epoch_no,first_seq,last_seq,chain_head,seal_tag FROM collector_integrity_epoch "
                + "WHERE node_id=? ORDER BY epoch_no",
            (rs, row) -> new ForwardSecureSeal.Epoch(rs.getLong("epoch_no"), rs.getLong("first_seq"),
                rs.getLong("last_seq"), rs.getString("chain_head"), rs.getString("seal_tag")), node);
        long expectedEpoch = 0;
        long verifiedThrough = 0;
        for (ForwardSecureSeal.Epoch epoch : epochs) {
          if (epoch.epoch() != expectedEpoch || epoch.firstSeq() != verifiedThrough + 1
              || epoch.lastSeq() < epoch.firstSeq()
              || !Objects.equals(hashes.get(epoch.lastSeq()), epoch.chainHead())
              || replay.verify(node, epoch) != ForwardSecureSeal.Result.OK) {
            return "BAD_SEAL";
          }
          expectedEpoch++;
          verifiedThrough = epoch.lastSeq();
        }
        ForwardSecureSeal.State replayed = replay.exportState();
        ForwardSecureSeal.State persisted = stored.state().ratchetState();
        if (verifiedThrough != stored.lastSealedSeq()
            || replayed.epoch() != persisted.epoch()
            || !MessageDigest.isEqual(replayed.key(), persisted.key())
            || !MessageDigest.isEqual(replayed.previousTag(), persisted.previousTag())) {
          return "BAD_RATCHET_STATE";
        }
      }
    } catch (IllegalStateException ex) {
      return "NO_RATCHET_STATE";
    }
    return "OK";
  }

  private byte[] ratchetEncryptionKey(String node) throws GeneralSecurityException {
    return c.hkdf(psk, node.getBytes(StandardCharsets.UTF_8),
        "pqh/collector-integrity-state/v1".getBytes(StandardCharsets.UTF_8), 32);
  }

  private byte[] ratchetAad(String node) {
    return (node + "|collector-integrity-state|v1").getBytes(StandardCharsets.UTF_8);
  }

  private byte[] encryptRatchetState(String node, byte[] plaintext) throws GeneralSecurityException {
    byte[] key = ratchetEncryptionKey(node);
    try { return IntegrityStateCodec.encrypt(key, plaintext, ratchetAad(node)); }
    finally { Arrays.fill(key, (byte) 0); }
  }

  private void persistRatchet(String node, IntegrityStateCodec.State state, long lastSealed) {
    try {
      byte[] plaintext = IntegrityStateCodec.encode(state);
      try {
        db.update("UPDATE collector_integrity_state SET encrypted_state=?,last_sealed_seq=? WHERE node_id=?",
            encryptRatchetState(node, plaintext), lastSealed, node);
      } finally {
        Arrays.fill(plaintext, (byte) 0);
      }
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("could not persist collector ratchet state", ex);
    }
  }
  private Map<String, Object> audit(String node, String result, String detail) { db.update("INSERT INTO audit_log(node_id,result,detail) VALUES(?,?,?)", node, result, detail); return Map.of("status", result, "detail", detail); }
  private static final class ForwardConcat { static byte[] concat(byte[] a, byte[] b) { byte[] o = Arrays.copyOf(a, a.length + b.length); System.arraycopy(b, 0, o, a.length, b.length); return o; } }
}
