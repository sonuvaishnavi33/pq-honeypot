package pqh.honeypot;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pqh.crypto.CryptoService;
import pqh.crypto.Ev;
import pqh.crypto.HashChain;
import pqh.research.ForwardSecureSeal;
import pqh.research.CheckpointSigner;
import pqh.research.IntegrityMode;
import pqh.research.IntegrityProperties;
import pqh.research.IntegrityStateCodec;

@Service
@Profile("honeypot")
public class EpochIntegrityService {
  private static final String STATE_AAD_SUFFIX = "|source-integrity-state|v1";
  private static final byte[] STATE_KEY_INFO = "pqh/source-integrity-state/v1".getBytes(StandardCharsets.UTF_8);

  private record LocalEvent(Ev event, String previousHash, String hash) {}

  private final JdbcTemplate db;
  private final CryptoService crypto;
  private final IntegrityProperties properties;
  private final byte[] psk;
  private final String node;
  private final PrivateKey checkpointPrivateKey;
  private final PublicKey checkpointPublicKey;

  public EpochIntegrityService(JdbcTemplate db, CryptoService crypto, IntegrityProperties properties,
                               @Value("${app.psk}") String psk, @Value("${app.node-id}") String node) {
    this.db = db;
    this.crypto = crypto;
    this.properties = properties;
    this.psk = psk.getBytes(StandardCharsets.UTF_8);
    this.node = node;
    if (properties.mode().anchor) {
      String privateMaterial = CheckpointSigner.readKeyMaterial(properties.checkpointPrivateKey(),
          properties.checkpointPrivateKeyFile(), "private");
      String publicMaterial = CheckpointSigner.readKeyMaterial(properties.checkpointPublicKey(),
          properties.checkpointPublicKeyFile(), "public");
      if (privateMaterial == null || privateMaterial.isBlank()
          || publicMaterial == null || publicMaterial.isBlank()) {
        throw new IllegalStateException(
            "checkpoint mode requires checkpoint private and public key material");
      }
      this.checkpointPrivateKey = CheckpointSigner.decodePrivateKey(privateMaterial);
      this.checkpointPublicKey = CheckpointSigner.decodePublicKey(publicMaterial);
      if (!CheckpointSigner.matches(checkpointPrivateKey, checkpointPublicKey)) {
        throw new IllegalStateException("configured ML-DSA checkpoint key pair does not match");
      }
    } else {
      this.checkpointPrivateKey = null;
      this.checkpointPublicKey = null;
    }
  }

  @Transactional
  public synchronized void eventRecorded() {
    if (!integrityEnabled()) return;
    try {
      sealIfDue(System.currentTimeMillis());
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("could not persist source integrity state", ex);
    }
  }

  @Scheduled(fixedDelayString = "${pqh.integrity.seal-interval-ms}")
  @Transactional
  public synchronized void scheduledSeal() {
    if (!integrityEnabled()) return;
    try {
      sealIfDue(System.currentTimeMillis());
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("could not persist source integrity state", ex);
    }
  }

  @Transactional
  public synchronized void sealPending() {
    if (!integrityEnabled()) return;
    try {
      long latest = latestEventSequence();
      long sealedThrough = latestSealedSequence();
      if (latest > sealedThrough) sealRange(sealedThrough + 1, latest);
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("could not persist source integrity state", ex);
    }
  }

  public synchronized byte[] streamSeed() {
    if (!properties.mode().ratchet) return new byte[0];
    try {
      return loadState().streamSeed();
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("could not load source integrity state", ex);
    }
  }

  @Transactional
  public synchronized void markSeedBootstrapped() {
    if (!properties.mode().ratchet) return;
    try {
      IntegrityStateCodec.State current = loadState();
      if (current.streamSeed().length > 0) {
        persistState(new IntegrityStateCodec.State(new byte[0], current.ratchetState()));
      }
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("could not erase bootstrapped source ratchet seed", ex);
    }
  }

  public boolean ratchetEnabled() { return properties.mode().ratchet; }
  public boolean checkpointEnabled() { return properties.mode().anchor; }

  public List<ForwardSecureSeal.Epoch> sealsAfter(long lastVerifiedSequence, long throughSequence) {
    if (!properties.mode().ratchet || throughSequence <= lastVerifiedSequence) return List.of();
    return db.query("SELECT epoch_no,first_seq,last_seq,chain_head,seal_tag FROM integrity_epoch "
            + "WHERE node_id=? AND seal_tag IS NOT NULL AND last_seq>? AND last_seq<=? ORDER BY epoch_no",
        (rs, row) -> new ForwardSecureSeal.Epoch(rs.getLong("epoch_no"), rs.getLong("first_seq"),
            rs.getLong("last_seq"), rs.getString("chain_head"), rs.getString("seal_tag")),
        node, lastVerifiedSequence, throughSequence);
  }

  public List<CheckpointSigner.Checkpoint> checkpointsAfter(long lastVerifiedSequence, long throughSequence) {
    if (!properties.mode().anchor || throughSequence <= lastVerifiedSequence) return List.of();
    return db.query("SELECT epoch_no,last_seq,chain_head,checkpoint_timestamp,checkpoint_signature "
            + "FROM integrity_epoch WHERE node_id=? AND checkpoint_signature IS NOT NULL "
            + "AND last_seq>? AND last_seq<=? ORDER BY epoch_no",
        (rs, row) -> new CheckpointSigner.Checkpoint(rs.getLong("epoch_no"), rs.getLong("last_seq"),
            rs.getString("chain_head"), rs.getLong("checkpoint_timestamp"),
            rs.getBytes("checkpoint_signature")), node, lastVerifiedSequence, throughSequence);
  }

  public synchronized long unsealedCount() {
    return Math.max(0, latestEventSequence() - latestSealedSequence());
  }

  public synchronized long forwardableThroughSequence() {
    return integrityEnabled() ? latestSealedSequence() : Long.MAX_VALUE;
  }

  @Transactional
  public synchronized void reset() {
    db.update("DELETE FROM integrity_epoch WHERE node_id=?", node);
    db.update("DELETE FROM integrity_stream_state WHERE node_id=?", node);
  }

  private void sealIfDue(long now) throws GeneralSecurityException {
    long last = latestEventSequence();
    long sealedThrough = latestSealedSequence();
    long count = last - sealedThrough;
    if (count <= 0) return;
    long first = sealedThrough + 1;
    long firstEventAt = firstUnsealedEventTime(first);
    boolean sizeReached = count >= properties.epochSize();
    boolean intervalReached = now - firstEventAt >= properties.sealIntervalMs();
    if (sizeReached || intervalReached) sealRange(first, last);
  }

  private void sealRange(long first, long last) throws GeneralSecurityException {
    List<LocalEvent> events = db.query("SELECT seq_no,event_time,source_ip,username,endpoint,http_method,"
            + "user_agent,risk_score,risk_level,rules_hit,prev_hash,chain_hash FROM security_event "
            + "WHERE seq_no BETWEEN ? AND ? ORDER BY seq_no",
        (rs, row) -> new LocalEvent(
            new Ev(rs.getLong("seq_no"), rs.getString("event_time"), rs.getString("source_ip"),
                rs.getString("username"), rs.getString("endpoint"), rs.getString("http_method"),
                rs.getString("user_agent"), rs.getInt("risk_score"), rs.getString("risk_level"),
                rs.getString("rules_hit")),
            rs.getString("prev_hash"), rs.getString("chain_hash")), first, last);
    if (events.size() != last - first + 1) {
      throw new IllegalStateException("cannot seal a non-contiguous source event range");
    }
    String previous = events.get(0).previousHash();
    List<HashChain.Link> links = new ArrayList<>(events.size());
    for (LocalEvent event : events) {
      links.add(new HashChain.Link(event.event().seq(), event.event().canonical(), event.hash()));
    }
    if (HashChain.verify(previous, first, links) >= 0) {
      throw new SecurityException("refusing to seal a locally invalid hash-chain range");
    }
    String head = events.get(events.size() - 1).hash();
    IntegrityStateCodec.State current = properties.mode().ratchet ? loadState() : null;
    long epochNo = current == null ? nextLocalEpoch() : current.ratchetState().epoch();
    ForwardSecureSeal.Epoch seal = null;
    ForwardSecureSeal.State nextRatchetState = null;
    if (current != null) {
      try (ForwardSecureSeal.Sealer sealer = new ForwardSecureSeal.Sealer(current.ratchetState())) {
        seal = sealer.seal(node, first, last, head);
        nextRatchetState = sealer.exportState();
      }
    }
    long checkpointTimestamp = 0;
    byte[] checkpointSignature = null;
    if (properties.mode().anchor && (epochNo + 1) % properties.checkpointEveryEpochs() == 0) {
      checkpointTimestamp = System.currentTimeMillis();
      checkpointSignature = CheckpointSigner.sign(checkpointPrivateKey, node, epochNo, last, head,
          checkpointTimestamp);
    }
    db.update("INSERT INTO integrity_epoch(node_id,epoch_no,first_seq,last_seq,chain_head,seal_tag,"
            + "sealed_at_ms,checkpoint_timestamp,checkpoint_signature) VALUES(?,?,?,?,?,?,?,?,?)",
        node, epochNo, first, last, head, seal == null ? null : seal.tag(), System.currentTimeMillis(),
        checkpointSignature == null ? null : checkpointTimestamp, checkpointSignature);
    if (current != null) {
      persistState(new IntegrityStateCodec.State(current.streamSeed(), nextRatchetState));
    }
  }

  private IntegrityStateCodec.State loadState() throws GeneralSecurityException {
    byte[] encrypted = db.query("SELECT encrypted_state FROM integrity_stream_state WHERE node_id=?",
        rs -> rs.next() ? rs.getBytes(1) : null, node);
    if (encrypted == null) {
      byte[] seed = new byte[32];
      new SecureRandom().nextBytes(seed);
      try (ForwardSecureSeal.Sealer sealer = new ForwardSecureSeal.Sealer(seed)) {
        IntegrityStateCodec.State initial = new IntegrityStateCodec.State(seed, sealer.exportState());
        persistState(initial);
        Arrays.fill(seed, (byte) 0);
        return initial;
      }
    }
    byte[] encryptionKey = stateEncryptionKey();
    try {
      return IntegrityStateCodec.decode(IntegrityStateCodec.decrypt(encryptionKey, encrypted, stateAad()));
    } finally {
      Arrays.fill(encryptionKey, (byte) 0);
    }
  }

  private void persistState(IntegrityStateCodec.State state) throws GeneralSecurityException {
    byte[] encryptionKey = stateEncryptionKey();
    byte[] plaintext = IntegrityStateCodec.encode(state);
    try {
      byte[] encrypted = IntegrityStateCodec.encrypt(encryptionKey, plaintext, stateAad());
      db.update("INSERT INTO integrity_stream_state(node_id,encrypted_state) VALUES(?,?) "
              + "ON DUPLICATE KEY UPDATE encrypted_state=VALUES(encrypted_state)",
          node, encrypted);
    } finally {
      Arrays.fill(encryptionKey, (byte) 0);
      Arrays.fill(plaintext, (byte) 0);
    }
  }

  private byte[] stateEncryptionKey() throws GeneralSecurityException {
    return crypto.hkdf(psk, node.getBytes(StandardCharsets.UTF_8), STATE_KEY_INFO, 32);
  }

  private byte[] stateAad() {
    return (node + STATE_AAD_SUFFIX).getBytes(StandardCharsets.UTF_8);
  }

  private long latestEventSequence() {
    Long sequence = db.queryForObject("SELECT COALESCE(MAX(seq_no),0) FROM security_event", Long.class);
    return sequence == null ? 0 : sequence;
  }

  private long latestSealedSequence() {
    Long sequence = db.queryForObject("SELECT COALESCE(MAX(last_seq),0) FROM integrity_epoch WHERE node_id=?",
        Long.class, node);
    return sequence == null ? 0 : sequence;
  }

  private long nextLocalEpoch() {
    Long epoch = db.queryForObject("SELECT COALESCE(MAX(epoch_no),-1)+1 FROM integrity_epoch WHERE node_id=?",
        Long.class, node);
    return epoch == null ? 0 : epoch;
  }

  private boolean integrityEnabled() {
    return properties.mode().ratchet || properties.mode().anchor;
  }

  private long firstUnsealedEventTime(long first) {
    String time = db.queryForObject("SELECT event_time FROM security_event WHERE seq_no=?",
        String.class, first);
    return Instant.parse(time).toEpochMilli();
  }
}
