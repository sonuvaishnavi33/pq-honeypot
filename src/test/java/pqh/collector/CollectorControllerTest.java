package pqh.collector;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.ResultSetExtractor;
import pqh.crypto.CryptoService;
import pqh.crypto.Ev;
import pqh.research.CheckpointSigner;
import pqh.research.ForwardSecureSeal;
import pqh.research.HybridKem;
import pqh.research.IntegrityMode;
import pqh.research.IntegrityProperties;
import pqh.research.KemProperties;

class CollectorControllerTest {
  private static final String NODE = "honeypot-01";
  private static final String STORED_HASH_QUERY =
      "SELECT chain_hash FROM evidence_record WHERE node_id=? AND seq_no=?";

  @Test
  void verifiesBackfilledSealsAgainstRecordsAlreadyStoredAtCollector() {
    JdbcTemplate db = mock(JdbcTemplate.class);
    mockStoredHash(db, "head-371");
    CollectorController controller = controller(db);
    byte[] seed = new byte[32];

    try (ForwardSecureSeal.Sealer sealer = new ForwardSecureSeal.Sealer(seed);
         ForwardSecureSeal.Verifier verifier = new ForwardSecureSeal.Verifier(seed)) {
      List<ForwardSecureSeal.Epoch> seals = List.of(
          sealer.seal(NODE, 1, 371, "head-371"),
          sealer.seal(NODE, 372, 372, "head-372"),
          sealer.seal(NODE, 373, 373, "head-373"));
      List<Ev.Rec> records = List.of(record(372, "head-372"), record(373, "head-373"));

      assertEquals(373, controller.verifySeals(NODE, seals, records, 372, 373, 0, verifier));
      assertEquals(3, verifier.exportState().epoch());
    }
  }

  @Test
  void rejectsBackfilledSealWhoseHeadDiffersFromStoredEvidence() {
    JdbcTemplate db = mock(JdbcTemplate.class);
    mockStoredHash(db, "wrong-head");
    CollectorController controller = controller(db);
    byte[] seed = new byte[32];

    try (ForwardSecureSeal.Sealer sealer = new ForwardSecureSeal.Sealer(seed);
         ForwardSecureSeal.Verifier verifier = new ForwardSecureSeal.Verifier(seed)) {
      List<ForwardSecureSeal.Epoch> seals = List.of(
          sealer.seal(NODE, 1, 371, "head-371"));

      assertEquals(-1, controller.verifySeals(NODE, seals, List.of(record(372, "head-372")),
          372, 372, 0, verifier));
    }
  }

  @Test
  void verifiesBackfilledCheckpointsAgainstRecordsAlreadyStoredAtCollector() {
    JdbcTemplate db = mock(JdbcTemplate.class);
    mockStoredHash(db, "head-371");
    doReturn(-1L).when(db).queryForObject(
        eq("SELECT COALESCE(MAX(epoch_no),-1) FROM collector_integrity_checkpoint WHERE node_id=?"),
        eq(Long.class), eq(NODE));
    var keys = CheckpointSigner.generate();
    String privateKey = Base64.getEncoder().encodeToString(keys.getPrivate().getEncoded());
    String publicKey = Base64.getEncoder().encodeToString(keys.getPublic().getEncoded());
    CollectorController controller = new CollectorController(new CryptoService(), db, new ObjectMapper(),
        "test-psk", 60, true,
        new IntegrityProperties(IntegrityMode.FULL, 32, 5000, 1,
            privateKey, publicKey, null, null),
        new KemProperties(HybridKem.Mode.X25519));
    List<CheckpointSigner.Checkpoint> checkpoints = List.of(
        checkpoint(keys, 0, 371, "head-371"),
        checkpoint(keys, 1, 372, "head-372"));

    assertTrue(controller.verifyCheckpoints(NODE, checkpoints,
        List.of(record(372, "head-372")), 372, 372));
  }

  private static void mockStoredHash(JdbcTemplate db, String hash) {
    doReturn(hash).when(db).query(eq(STORED_HASH_QUERY),
        org.mockito.ArgumentMatchers.<ResultSetExtractor<String>>any(), eq(NODE), eq(371L));
  }

  private static CollectorController controller(JdbcTemplate db) {
    return new CollectorController(new CryptoService(), db, new ObjectMapper(), "test-psk", 60, true,
        new IntegrityProperties(IntegrityMode.CHAIN_RATCHET, 32, 5000, 1,
            null, null, null, null),
        new KemProperties(HybridKem.Mode.X25519));
  }

  private static Ev.Rec record(long sequence, String hash) {
    return new Ev.Rec(new Ev(sequence, "2026-01-01T00:00:00Z", "192.0.2.1",
        null, "/login", "POST", "test", 0, "LOW", ""), hash);
  }

  private static CheckpointSigner.Checkpoint checkpoint(
      java.security.KeyPair keys, long epoch, long sequence, String hash) {
    long timestamp = 100L + epoch;
    return new CheckpointSigner.Checkpoint(epoch, sequence, hash, timestamp,
        CheckpointSigner.sign(keys.getPrivate(), NODE, epoch, sequence, hash, timestamp));
  }
}
