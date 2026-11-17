package pqh.research;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Self-contained model of honeypot + collector with real AES-GCM, SHA-256, HMAC ratchet and ML-DSA.
 * It defines what each integrity mode is EXPECTED to detect. Numbers from this model are NOT paper results:
 * paper numbers must come from RealTarget running against the real services.
 */
public final class ReferenceTarget implements EvidenceTarget {
    static final String NODE = "ref-node";

    @Override
    public Stream open(IntegrityMode mode, int epochSize, long seed) {
        return new Model(mode, epochSize, seed);
    }

    // ------------------------------------------------------------------ shared helpers

    static String sha(String... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(String.join("\u001f", parts).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(md.digest());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String genesis() { return sha("GENESIS", NODE); }

    static String link(String prev, Event e) { return sha(prev, String.valueOf(e.seq()), e.payload()); }

    static Chained chain(String prev, Event e) { return new Chained(e, prev, link(prev, e)); }

    static byte[] encode(Batch b) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);
        out.writeInt(b.events().size());
        for (Chained c : b.events()) {
            out.writeLong(c.event().seq());
            out.writeUTF(c.event().payload());
            out.writeUTF(c.prevHash());
            out.writeUTF(c.hash());
        }
        out.writeInt(b.seals().size());
        for (ForwardSecureSeal.Epoch s : b.seals()) {
            out.writeLong(s.epoch());
            out.writeLong(s.firstSeq());
            out.writeLong(s.lastSeq());
            out.writeUTF(s.chainHead());
            out.writeUTF(s.tag());
        }
        out.writeInt(b.checkpoints().size());
        for (Checkpoint c : b.checkpoints()) {
            out.writeLong(c.seq());
            out.writeUTF(c.hash());
            out.writeLong(c.timestamp());
            out.writeInt(c.signature().length);
            out.write(c.signature());
        }
        return bytes.toByteArray();
    }

    static Batch decode(byte[] data) throws IOException {
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));
        List<Chained> events = new ArrayList<>();
        for (int i = in.readInt(); i > 0; i--) {
            events.add(new Chained(new Event(in.readLong(), in.readUTF()), in.readUTF(), in.readUTF()));
        }
        List<ForwardSecureSeal.Epoch> seals = new ArrayList<>();
        for (int i = in.readInt(); i > 0; i--) {
            seals.add(new ForwardSecureSeal.Epoch(in.readLong(), in.readLong(), in.readLong(), in.readUTF(), in.readUTF()));
        }
        List<Checkpoint> cps = new ArrayList<>();
        for (int i = in.readInt(); i > 0; i--) {
            long seq = in.readLong();
            String hash = in.readUTF();
            long ts = in.readLong();
            byte[] sig = new byte[in.readInt()];
            in.readFully(sig);
            cps.add(new Checkpoint(seq, hash, ts, sig));
        }
        return new Batch(events, seals, cps);
    }

    static byte[] nonce(byte[] salt, long counter) {
        return ByteBuffer.allocate(12).put(salt).putLong(counter).array();
    }

    static byte[] aad(long counter) {
        return ("pqh/ref-aad|" + NODE + "|" + counter).getBytes(StandardCharsets.UTF_8);
    }

    static byte[] gcm(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] input) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        c.updateAAD(aad);
        return c.doFinal(input);
    }

    /** Sequence rules identical to the real ChainVerifier: DUPLICATE, OUT_OF_ORDER, GAP. Returns null when fine. */
    static String checkSequence(long expected, List<Chained> events) {
        boolean inOrder = true;
        for (int i = 0; i < events.size(); i++) {
            if (events.get(i).event().seq() != expected + i) { inOrder = false; break; }
        }
        if (inOrder) return null;
        if (events.stream().allMatch(c -> c.event().seq() < expected)) return "DUPLICATE";
        List<Long> sorted = new ArrayList<>();
        for (Chained c : events) sorted.add(c.event().seq());
        Collections.sort(sorted);
        boolean contiguous = true;
        for (int i = 0; i < sorted.size(); i++) {
            if (sorted.get(i) != expected + i) { contiguous = false; break; }
        }
        if (contiguous) return "OUT_OF_ORDER";
        if (events.stream().anyMatch(c -> c.event().seq() < expected)) return "DUPLICATE";
        return "GAP";
    }

    static String checkChain(String previous, List<Chained> events) {
        String prev = previous;
        for (Chained c : events) {
            if (!prev.equals(c.prevHash()) || !link(prev, c.event()).equals(c.hash())) return "CHAIN_BROKEN";
            prev = c.hash();
        }
        return null;
    }

    // ------------------------------------------------------------------ the model

    private static final class Model implements Stream {
        private final IntegrityMode mode;
        private final int epochSize;
        private final Random random;

        // honeypot
        private final byte[] sessionKey = new byte[32];
        private final byte[] ivSalt = new byte[4];
        private long counter;
        private final List<Chained> events = new ArrayList<>();
        private final List<int[]> bounds = new ArrayList<>();        // [fromIndex, toIndexInclusive] per sealed epoch
        private String head = genesis();
        private long nextSeq = 1;
        private int sealedUpTo, deliveredUpTo, sealsDelivered, checkpointsDelivered;
        private final byte[] ratchetSeed = new byte[32];
        private final ForwardSecureSeal.Sealer sealer;
        private final List<ForwardSecureSeal.Epoch> seals = new ArrayList<>();
        private final KeyPair signing;
        private final List<Checkpoint> checkpoints = new ArrayList<>();

        // collector
        private long lastCounter;
        private long expectedSeq = 1;
        private String collectorHead = genesis();
        private final List<Chained> stored = new ArrayList<>();
        private final List<Checkpoint> storedCheckpoints = new ArrayList<>();
        private ForwardSecureSeal.Verifier verifier;

        Model(IntegrityMode mode, int epochSize, long seed) {
            this.mode = mode;
            this.epochSize = epochSize;
            this.random = new Random(seed);
            random.nextBytes(sessionKey);
            random.nextBytes(ivSalt);
            random.nextBytes(ratchetSeed);
            this.sealer = mode.ratchet ? new ForwardSecureSeal.Sealer(ratchetSeed.clone()) : null;
            this.verifier = mode.ratchet ? new ForwardSecureSeal.Verifier(ratchetSeed.clone()) : null;
            this.signing = mode.anchor ? CheckpointSigner.generate() : null;
        }

        @Override public IntegrityMode mode() { return mode; }

        @Override public Random random() { return random; }

        @Override public long unsealedCount() { return events.size() - sealedUpTo; }

        @Override
        public List<Chained> generate(int count) {
            List<Chained> created = new ArrayList<>();
            for (int i = 0; i < count; i++) {
                Chained c = chain(head, new Event(nextSeq++, "evt-" + random.nextInt(100000)));
                events.add(c);
                created.add(c);
                head = c.hash();
                if (unsealedCount() >= epochSize) sealPending();
            }
            return created;
        }

        @Override
        public void sealPending() {
            if (unsealedCount() == 0) return;
            int from = sealedUpTo, to = events.size() - 1;
            long first = events.get(from).event().seq(), last = events.get(to).event().seq();
            if (mode.ratchet) seals.add(sealer.seal(NODE, first, last, events.get(to).hash()));
            if (mode.anchor) {
                long ts = System.currentTimeMillis();
                checkpoints.add(new Checkpoint(last, events.get(to).hash(), ts,
                        CheckpointSigner.sign(signing.getPrivate(), NODE, last, events.get(to).hash(), ts)));
            }
            bounds.add(new int[] {from, to});
            sealedUpTo = events.size();
        }

        @Override
        public Batch drainSealed() {
            Batch batch = new Batch(new ArrayList<>(events.subList(deliveredUpTo, sealedUpTo)),
                    new ArrayList<>(seals.subList(sealsDelivered, seals.size())),
                    new ArrayList<>(checkpoints.subList(checkpointsDelivered, checkpoints.size())));
            deliveredUpTo = sealedUpTo;
            sealsDelivered = seals.size();
            checkpointsDelivered = checkpoints.size();
            return batch;
        }

        @Override
        public Wire encrypt(Batch batch) {
            try {
                long c = ++counter;
                return new Wire(c, gcm(Cipher.ENCRYPT_MODE, sessionKey, nonce(ivSalt, c), aad(c), encode(batch)));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        @Override
        public String deliver(Wire wire) {
            if (wire.counter() <= lastCounter) return "REPLAY";
            byte[] plain;
            try {
                plain = gcm(Cipher.DECRYPT_MODE, sessionKey, nonce(ivSalt, wire.counter()), aad(wire.counter()), wire.ciphertext());
            } catch (Exception e) {
                return "TAMPERED";
            }
            lastCounter = wire.counter();
            Batch b;
            try {
                b = decode(plain);
            } catch (IOException e) {
                return "MALFORMED";
            }
            Map<Long, String> hashBySeq = new HashMap<>();
            for (Chained c : b.events()) hashBySeq.put(c.event().seq(), c.hash());

            if (mode.chain) {
                if (b.events().isEmpty()) return "MALFORMED";
                String v = checkSequence(expectedSeq, b.events());
                if (v == null) v = checkChain(collectorHead, b.events());
                if (v != null) return v;
            }
            ForwardSecureSeal.Verifier trial = null;
            if (mode.ratchet) {
                trial = new ForwardSecureSeal.Verifier(verifier.exportState());     // commit only if everything passes
                for (ForwardSecureSeal.Epoch e : b.seals()) {
                    ForwardSecureSeal.Result r = trial.verify(NODE, e);
                    if (r != ForwardSecureSeal.Result.OK) return r == ForwardSecureSeal.Result.BAD_TAG ? "BAD_SEAL" : r.name();
                    String actual = hashBySeq.get(e.lastSeq());
                    if (actual == null || !actual.equals(e.chainHead())) return "BAD_SEAL";
                }
                long lastEvent = b.events().isEmpty() ? 0 : b.events().get(b.events().size() - 1).event().seq();
                long lastSealed = b.seals().isEmpty() ? 0 : b.seals().get(b.seals().size() - 1).lastSeq();
                if (lastEvent > lastSealed) return "UNSEALED_EVENTS";
            }
            if (mode.anchor) {
                for (Checkpoint cp : b.checkpoints()) {
                    boolean signatureOk = CheckpointSigner.verify(signing.getPublic(), NODE, cp.seq(), cp.hash(), cp.timestamp(), cp.signature());
                    String actual = hashBySeq.get(cp.seq());
                    if (actual == null) {
                        for (Chained c : stored) if (c.event().seq() == cp.seq()) actual = c.hash();
                    }
                    if (!signatureOk || actual == null || !actual.equals(cp.hash())) return "BAD_CHECKPOINT";
                }
            }
            if (trial != null) verifier = trial;
            stored.addAll(b.events());
            storedCheckpoints.addAll(b.checkpoints());
            if (!b.events().isEmpty()) {
                Chained last = b.events().get(b.events().size() - 1);
                collectorHead = last.hash();
                expectedSeq = last.event().seq() + 1;
            }
            return "ACCEPTED";
        }

        @Override
        public String verifyStored() {
            if (mode.chain && checkChain(genesis(), stored) != null) return "CHAIN_BROKEN";
            if (mode.anchor) {
                for (Checkpoint cp : storedCheckpoints) {
                    String actual = null;
                    for (Chained c : stored) if (c.event().seq() == cp.seq()) actual = c.hash();
                    boolean ok = CheckpointSigner.verify(signing.getPublic(), NODE, cp.seq(), cp.hash(), cp.timestamp(), cp.signature());
                    if (!ok || actual == null || !actual.equals(cp.hash())) return "BAD_CHECKPOINT";
                }
            }
            return "OK";
        }

        @Override
        public void rewriteStoredChain(int index, String payload) {
            rechain(stored, index, payload, genesis());
        }

        @Override
        public Compromise compromise() { return new Attacker(); }

        private static void rechain(List<Chained> list, int index, String payload, String genesisHash) {
            String prev = index == 0 ? genesisHash : list.get(index - 1).hash();
            for (int i = index; i < list.size(); i++) {
                Event old = list.get(i).event();
                Chained c = chain(prev, i == index ? new Event(old.seq(), payload) : old);
                list.set(i, c);
                prev = c.hash();
            }
        }

        private final class Attacker implements Compromise {
            @Override
            public void rewriteLocal(int index, String payload) {
                rechain(events, index, payload, genesis());
                head = events.get(events.size() - 1).hash();
            }

            @Override
            public void dropUnsealedTail(int count) {
                for (int i = 0; i < count && events.size() > sealedUpTo; i++) {
                    events.remove(events.size() - 1);
                    nextSeq--;
                }
                head = events.isEmpty() ? genesis() : events.get(events.size() - 1).hash();
            }

            @Override
            public void injectUnsealed(String payload) {
                Chained c = chain(head, new Event(nextSeq++, payload));
                events.add(c);
                head = c.hash();
            }

            @Override
            public void forgeSealsFromEpoch(int firstEpoch) {
                byte[] stolenKey = mode.ratchet ? sealer.leakCurrentKeyForAttackSimulation() : null;
                byte[] previousTag = firstEpoch == 0 || !mode.ratchet ? new byte[32]
                        : HexFormat.of().parseHex(seals.get(firstEpoch - 1).tag());
                for (int e = firstEpoch; e < bounds.size(); e++) {
                    int from = bounds.get(e)[0], to = bounds.get(e)[1];
                    String newHead = events.get(to).hash();
                    long first = events.get(from).event().seq(), last = events.get(to).event().seq();
                    if (mode.ratchet) {
                        ForwardSecureSeal.Epoch forged = ForwardSecureSeal.forgeForSimulation(stolenKey, NODE, e, first, last, newHead, previousTag);
                        seals.set(e, forged);
                        previousTag = HexFormat.of().parseHex(forged.tag());
                    }
                    if (mode.anchor) {          // attacker also stole the signing key, so re-signing is possible
                        long ts = System.currentTimeMillis();
                        checkpoints.set(e, new Checkpoint(last, newHead, ts, CheckpointSigner.sign(signing.getPrivate(), NODE, last, newHead, ts)));
                    }
                }
            }

            @Override
            public Batch withForgedCheckpoint(Batch honest) {
                KeyPair own = CheckpointSigner.generate();
                List<Checkpoint> forged = new ArrayList<>();
                for (Checkpoint cp : honest.checkpoints()) {
                    forged.add(new Checkpoint(cp.seq(), cp.hash(), cp.timestamp(),
                            CheckpointSigner.sign(own.getPrivate(), NODE, cp.seq(), cp.hash(), cp.timestamp())));
                }
                return new Batch(honest.events(), honest.seals(), forged);
            }
        }
    }
}
