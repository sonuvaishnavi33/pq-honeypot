package pqh.research;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ResearchPrimitivesTest {
  @Test
  void ratchetDetectsModifiedEpochAndSupportsVerifierRestore() {
    byte[] seed = new byte[32];
    Arrays.fill(seed, (byte) 7);
    ForwardSecureSeal.Sealer sealer = new ForwardSecureSeal.Sealer(seed);
    ForwardSecureSeal.Epoch first = sealer.seal("node", 1, 4, "head-4");
    ForwardSecureSeal.Epoch second = sealer.seal("node", 5, 8, "head-8");
    ForwardSecureSeal.Verifier verifier = new ForwardSecureSeal.Verifier(seed);

    assertEquals(ForwardSecureSeal.Result.OK, verifier.verify("node", first));
    ForwardSecureSeal.Verifier restored = new ForwardSecureSeal.Verifier(verifier.exportState());
    assertEquals(ForwardSecureSeal.Result.BAD_TAG,
        restored.verify("node", new ForwardSecureSeal.Epoch(second.epoch(), second.firstSeq(),
            second.lastSeq(), "edited-head", second.tag())));
    assertEquals(ForwardSecureSeal.Result.OK, restored.verify("node", second));
    sealer.close();
    verifier.close();
    restored.close();
  }

  @Test
  void sealerStateCanBeRestoredWithoutReusingAnEpochKey() {
    byte[] seed = new byte[32];
    Arrays.fill(seed, (byte) 9);
    ForwardSecureSeal.Sealer original = new ForwardSecureSeal.Sealer(seed);
    original.seal("node", 1, 4, "head-4");
    ForwardSecureSeal.State state = original.exportState();
    ForwardSecureSeal.Epoch expected = original.seal("node", 5, 8, "head-8");
    ForwardSecureSeal.Sealer restored = new ForwardSecureSeal.Sealer(state);

    assertEquals(expected, restored.seal("node", 5, 8, "head-8"));
    original.close();
    restored.close();
  }

  @Test
  void persistedRatchetStateIsAuthenticatedAndVersioned() throws Exception {
    byte[] seed = new byte[32];
    byte[] key = new byte[32];
    Arrays.fill(seed, (byte) 3);
    Arrays.fill(key, (byte) 4);
    ForwardSecureSeal.State ratchet = new ForwardSecureSeal.State(key, 7, new byte[32]);
    IntegrityStateCodec.State state = new IntegrityStateCodec.State(seed, ratchet);
    byte[] encryptionKey = new byte[32];
    Arrays.fill(encryptionKey, (byte) 5);
    byte[] aad = "node|integrity-state|v1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    byte[] encrypted = IntegrityStateCodec.encrypt(encryptionKey, IntegrityStateCodec.encode(state), aad);

    IntegrityStateCodec.State restored = IntegrityStateCodec.decode(
        IntegrityStateCodec.decrypt(encryptionKey, encrypted, aad));
    assertArrayEquals(seed, restored.streamSeed());
    assertEquals(7, restored.ratchetState().epoch());
    assertArrayEquals(key, restored.ratchetState().key());
    assertThrows(java.security.GeneralSecurityException.class, () ->
        IntegrityStateCodec.decrypt(encryptionKey, encrypted,
            "other-node".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
  }

  @Test
  void persistedRatchetStateCanEraseItsBootstrapSeedAfterCollectorAcknowledgement() {
    byte[] key = new byte[32];
    Arrays.fill(key, (byte) 4);
    ForwardSecureSeal.State ratchet = new ForwardSecureSeal.State(key, 7, new byte[32]);
    IntegrityStateCodec.State state = new IntegrityStateCodec.State(new byte[0], ratchet);

    IntegrityStateCodec.State restored = IntegrityStateCodec.decode(IntegrityStateCodec.encode(state));

    assertEquals(0, restored.streamSeed().length);
    assertEquals(7, restored.ratchetState().epoch());
    assertArrayEquals(key, restored.ratchetState().key());
  }

  @Test
  void hybridModesDeriveTheSameSecretAtBothEnds() throws Exception {
    for (HybridKem.Mode mode : HybridKem.Mode.values()) {
      HybridKem.ServerKeys server = HybridKem.generate(mode);
      HybridKem.ClientResult client = HybridKem.encapsulate(mode,
          server.x25519() == null ? null : server.x25519().getPublic(),
          server.mlKem() == null ? null : server.mlKem().getPublic());
      byte[] decoded = HybridKem.decapsulate(mode, server, client.offer());
      assertArrayEquals(client.sharedSecret(), decoded);
      assertTrue(client.offer().wireBytes() > 0);
      client.close();
      Arrays.fill(decoded, (byte) 0);
    }
  }

  @Test
  void checkpointSignatureBindsCheckpointFields() {
    var keys = CheckpointSigner.generate();
    byte[] signature = CheckpointSigner.sign(keys.getPrivate(), "node", 9, "chain-head", 12L);

    assertTrue(CheckpointSigner.verify(keys.getPublic(), "node", 9, "chain-head", 12L, signature));
    assertFalse(CheckpointSigner.verify(keys.getPublic(), "node", 10, "chain-head", 12L, signature));
  }

  @Test
  void checkpointKeysCanBeReadFromFilesWithoutAcceptingAmbiguousConfiguration() throws Exception {
    Path file = Files.createTempFile("pqh-checkpoint-public-", ".key");
    try {
      Files.writeString(file, "  public-key-material  ");
      assertEquals("public-key-material",
          CheckpointSigner.readKeyMaterial("", file.toString(), "public"));
      assertThrows(IllegalArgumentException.class, () ->
          CheckpointSigner.readKeyMaterial("inline", file.toString(), "public"));
    } finally {
      Files.deleteIfExists(file);
    }
  }

  @Test
  void checkpointKeygenWritesAUsablePairWithoutOverwritingFiles(@TempDir Path directory)
      throws Exception {
    Path privateFile = directory.resolve("private.key");
    Path publicFile = directory.resolve("public.key");

    CheckpointKeygenMain.main(new String[] {privateFile.toString(), publicFile.toString()});

    var privateKey = CheckpointSigner.decodePrivateKey(Files.readString(privateFile));
    var publicKey = CheckpointSigner.decodePublicKey(Files.readString(publicFile));
    assertTrue(CheckpointSigner.matches(privateKey, publicKey));
    assertThrows(IllegalArgumentException.class, () ->
        CheckpointKeygenMain.main(new String[] {privateFile.toString(), publicFile.toString()}));
  }

  @Test
  void viewsAreBoundedAndReportDecodeProvenance() {
    PayloadViews.Views views = PayloadViews.of("/admin?q=union%2520select", 2);

    assertEquals(2, views.decodeRounds());
    assertTrue(views.texts().contains("/admin?q=union select"));
    assertFalse(views.malformedEncoding());
    assertTrue(PayloadViews.of("/x?a=%zz", 3).malformedEncoding());
  }

  @Test
  void statisticsUseNearestRankAndWilsonIntervals() {
    assertEquals(50, Stats.percentile(new double[] {10, 20, 30, 40, 50}, 95));
    double[] interval = Stats.wilson(20, 20, 1.96);
    assertTrue(interval[0] < 1);
    assertTrue(interval[0] > 0.8);
    assertEquals(1, interval[1]);
  }
}
