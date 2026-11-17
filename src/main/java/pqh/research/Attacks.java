package pqh.research;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import pqh.research.AttackMatrix.Attack;
import pqh.research.AttackMatrix.Outcome;
import pqh.research.EvidenceTarget.Batch;
import pqh.research.EvidenceTarget.Chained;
import pqh.research.EvidenceTarget.Compromise;
import pqh.research.EvidenceTarget.Event;
import pqh.research.EvidenceTarget.Stream;
import pqh.research.EvidenceTarget.Wire;

/** The twelve attacks of the tamper-evidence matrix. They only use the EvidenceTarget interface. */
public final class Attacks {
    private Attacks() {}

    @FunctionalInterface
    private interface Body { Outcome run(Stream s, IntegrityMode mode) throws Exception; }

    /** Seal after this many events never happens automatically in the matrix; each attack seals when it wants to. */
    private static final int MANUAL_SEAL = Integer.MAX_VALUE;

    public static List<Attack> all(EvidenceTarget target, IntegrityMode mode) {
        List<Attack> list = new ArrayList<>();

        list.add(attack(target, mode, "A1_ciphertext_bitflip", "Network attacker flips one ciphertext bit", (s, m) -> {
            Wire w = honestWire(s, 5);
            byte[] c = w.ciphertext().clone();
            c[c.length / 2] ^= 0x01;
            return verdict(s.deliver(new Wire(w.counter(), c)), 0);
        }));

        list.add(attack(target, mode, "A2_replay_same_wire", "Network attacker replays an accepted ciphertext", (s, m) -> {
            Wire w = honestWire(s, 5);
            expectAccepted(s.deliver(w));
            return verdict(s.deliver(w), 0);
        }));

        list.add(attack(target, mode, "A3_resend_old_events_fresh_counter", "Compromised sender re-encrypts events already delivered", (s, m) -> {
            s.generate(5);
            s.sealPending();
            Batch b = s.drainSealed();
            expectAccepted(s.deliver(s.encrypt(b)));
            return verdict(s.deliver(s.encrypt(b)), 0);
        }));

        list.add(attack(target, mode, "A4_delete_event_in_batch", "Attacker removes one event before encryption", (s, m) -> {
            Batch b = honestBatch(s, 5);
            List<Chained> events = new ArrayList<>(b.events());
            events.remove(2);
            return verdict(s.deliver(s.encrypt(new Batch(events, b.seals(), b.checkpoints()))), 0);
        }));

        list.add(attack(target, mode, "A5_swap_two_events", "Attacker swaps two events", (s, m) -> {
            Batch b = honestBatch(s, 5);
            List<Chained> events = new ArrayList<>(b.events());
            Collections.swap(events, 1, 2);
            return verdict(s.deliver(s.encrypt(new Batch(events, b.seals(), b.checkpoints()))), 0);
        }));

        list.add(attack(target, mode, "A6_edit_content_keep_hash", "Attacker edits an event but keeps its old hash", (s, m) -> {
            Batch b = honestBatch(s, 5);
            List<Chained> events = new ArrayList<>(b.events());
            Chained old = events.get(2);
            events.set(2, new Chained(new Event(old.event().seq(), "edited-by-attacker"), old.prevHash(), old.hash()));
            return verdict(s.deliver(s.encrypt(new Batch(events, b.seals(), b.checkpoints()))), 0);
        }));

        list.add(attack(target, mode, "A7_tail_truncation", "Attacker erases the newest UNSEALED events and re-chains", (s, m) -> {
            s.generate(6);
            s.sealPending();
            expectAccepted(s.deliver(s.encrypt(s.drainSealed())));
            s.generate(8);
            long exposed = s.unsealedCount();
            s.compromise().dropUnsealedTail(3);
            s.sealPending();
            return verdict(s.deliver(s.encrypt(s.drainSealed())), exposed);
        }));

        list.add(attack(target, mode, "A8_rewrite_delivered_history", "Root attacker rewrites already delivered history, then keeps sending", (s, m) -> {
            s.generate(6);
            s.sealPending();
            expectAccepted(s.deliver(s.encrypt(s.drainSealed())));
            s.generate(4);
            s.sealPending();
            s.compromise().rewriteLocal(1, "rewritten-history");
            return verdict(s.deliver(s.encrypt(s.drainSealed())), 0);
        }));

        list.add(attack(target, mode, "A9_forged_checkpoint_wrong_key", "Forwarder swaps in a checkpoint signed with the attacker's own key", (s, m) -> {
            if (!m.anchor) return Outcome.notApplicable();
            Batch b = honestBatch(s, 5);
            Batch forged = s.compromise().withForgedCheckpoint(b);
            return verdict(s.deliver(s.encrypt(forged)), 0);
        }));

        list.add(attack(target, mode, "A10_backlog_rewrite_during_outage", "Collector offline: root attacker rewrites sealed, undelivered epochs, re-chains and re-signs", (s, m) -> {
            for (int epoch = 0; epoch < 3; epoch++) {
                s.generate(5);
                s.sealPending();
            }
            Compromise c = s.compromise();
            c.rewriteLocal(7, "rewritten-in-sealed-epoch");
            c.forgeSealsFromEpoch(1);
            return verdict(s.deliver(s.encrypt(s.drainSealed())), 0);
        }));

        list.add(attack(target, mode, "A11_inject_into_unsealed_epoch", "Root attacker fabricates events in the current unsealed epoch", (s, m) -> {
            s.generate(5);
            s.sealPending();
            expectAccepted(s.deliver(s.encrypt(s.drainSealed())));
            s.generate(4);
            long exposed = s.unsealedCount();
            s.compromise().injectUnsealed("fabricated-admin-login");
            s.sealPending();
            return verdict(s.deliver(s.encrypt(s.drainSealed())), exposed);
        }));

        list.add(attack(target, mode, "A12_collector_db_consistent_rewrite", "Attacker with collector DB write access rewrites the stored chain consistently", (s, m) -> {
            s.generate(8);
            s.sealPending();
            expectAccepted(s.deliver(s.encrypt(s.drainSealed())));
            s.rewriteStoredChain(3, "rewritten-on-collector");
            return verdict(s.verifyStored(), 0);
        }));

        return List.copyOf(list);
    }

    private static Attack attack(EvidenceTarget target, IntegrityMode mode, String id, String description, Body body) {
        return new Attack() {
            @Override public String id() { return id; }

            @Override public String description() { return description; }

            @Override
            public Outcome run(long seed) throws Exception {
                return body.run(target.open(mode, MANUAL_SEAL, seed), mode);
            }
        };
    }

    private static Batch honestBatch(Stream s, int events) {
        s.generate(events);
        s.sealPending();
        return s.drainSealed();
    }

    private static Wire honestWire(Stream s, int events) { return s.encrypt(honestBatch(s, events)); }

    private static void expectAccepted(String verdict) {
        if (!"ACCEPTED".equals(verdict)) throw new IllegalStateException("honest step was rejected: " + verdict);
    }

    /** ACCEPTED (or an OK stored-evidence check) means the attack went UNDETECTED. */
    private static Outcome verdict(String verdict, long exposedEvents) {
        boolean detected = !"ACCEPTED".equals(verdict) && !"OK".equals(verdict);
        return new Outcome(detected, verdict, exposedEvents);
    }
}
