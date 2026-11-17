package pqh.research;

import java.util.List;
import java.util.Random;

/**
 * The seam between the experiments and your real system. ReferenceTarget implements it with a small in-memory model
 * (useful to understand the expected behaviour). Your task: write RealTarget that implements the SAME interface on top of the
 * real honeypot and collector classes, then run the unchanged Attacks and AttackMatrixMain against it.
 */
public interface EvidenceTarget {

    /** Fresh node, fresh keys, empty history. epochSize = events per locally sealed epoch (use a huge value to seal manually). */
    Stream open(IntegrityMode mode, int epochSize, long seed) throws Exception;

    record Event(long seq, String payload) {}

    record Chained(Event event, String prevHash, String hash) {}

    record Checkpoint(long seq, String hash, long timestamp, byte[] signature) {}

    record Batch(List<Chained> events, List<ForwardSecureSeal.Epoch> seals, List<Checkpoint> checkpoints) {}

    /** What an eavesdropper or man-in-the-middle sees: an AES-GCM ciphertext and its counter. */
    record Wire(long counter, byte[] ciphertext) {}

    /** One honeypot-to-collector evidence stream. */
    interface Stream {
        IntegrityMode mode();

        Random random();

        /** The honeypot logs events locally (chained, not yet sealed). Seals automatically every epochSize events. */
        List<Chained> generate(int count);

        /** Seals all unsealed events as one epoch (+ checkpoint in anchor modes). */
        void sealPending();

        /** Honest forwarder: takes every sealed, undelivered event plus its seals and checkpoints. */
        Batch drainSealed();

        Wire encrypt(Batch batch);

        /** Collector side. Returns ACCEPTED or the rejection verdict (TAMPERED, REPLAY, GAP, ...). */
        String deliver(Wire wire);

        /** The attacker gets root on the honeypot at this moment. */
        Compromise compromise();

        /** Collector re-verifies everything it stored. Returns OK or the failing verdict. */
        String verifyStored();

        /** Attacker with WRITE access to the collector database edits one stored event and recomputes the chain after it. */
        void rewriteStoredChain(int eventIndex, String newPayload);

        /** Events that are logged but not yet sealed: the exposure window. */
        long unsealedCount();
    }

    /** Capabilities of an attacker who owns the honeypot process: local data, the current ratchet key and the signing key. */
    interface Compromise {
        /** Edits a local event and recomputes every later hash (possible because SHA-256 is unkeyed). */
        void rewriteLocal(int eventIndex, String newPayload);

        void dropUnsealedTail(int count);

        void injectUnsealed(String payload);

        /** Recreates seals and checkpoints for epochs >= firstEpoch using whatever keys were stolen. */
        void forgeSealsFromEpoch(int firstEpoch);

        /** Replaces every checkpoint of the batch with one signed by the attacker's OWN key (the real key was not stolen). */
        Batch withForgedCheckpoint(Batch honest);
    }
}
