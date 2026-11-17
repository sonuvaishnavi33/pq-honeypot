package pqh.research;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/** Runnable proof of the three new mechanisms, with no Spring or database needed: java pqh.research.ResearchSelfCheck */
public final class ResearchSelfCheck {
    private static int failures;

    public static void main(String[] args) {
        ratchetProperties();
        payloadViews();
        statistics();
        hybridKem();
        System.out.println(failures == 0 ? "ALL CHECKS PASSED" : failures + " CHECK(S) FAILED");
        if (failures > 0) System.exit(1);
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "PASS  " : "FAIL  ") + name);
        if (!ok) failures++;
    }

    private static void ratchetProperties() {
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        ForwardSecureSeal.Sealer sealer = new ForwardSecureSeal.Sealer(seed.clone());
        ForwardSecureSeal.Verifier verifier = new ForwardSecureSeal.Verifier(seed.clone());

        List<ForwardSecureSeal.Epoch> epochs = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            ForwardSecureSeal.Epoch e = sealer.seal("honeypot-01", i * 10L + 1, i * 10L + 10, "head" + i);
            epochs.add(e);
            check("honest epoch " + i + " verifies", verifier.verify("honeypot-01", e) == ForwardSecureSeal.Result.OK);
        }

        check("replayed epoch is refused", verifier.verify("honeypot-01", epochs.get(2)) == ForwardSecureSeal.Result.REPLAYED_EPOCH);

        // Attacker dumps memory after epoch 5 and tries to rewrite history.
        byte[] stolenKey = sealer.leakCurrentKeyForAttackSimulation();
        ForwardSecureSeal.Verifier fresh = new ForwardSecureSeal.Verifier(seed.clone());
        ForwardSecureSeal.Epoch forgedOld = new ForwardSecureSeal.Epoch(2, 21, 30, "forged-head",
                java.util.HexFormat.of().formatHex(ForwardSecureSeal.mac(stolenKey, "mac", new byte[] {1})));
        for (int i = 0; i < 2; i++) fresh.verify("honeypot-01", epochs.get(i));
        check("forged tag for an OLD epoch using the stolen key is rejected",
                fresh.verify("honeypot-01", forgedOld) == ForwardSecureSeal.Result.BAD_TAG);

        ForwardSecureSeal.Epoch edited = new ForwardSecureSeal.Epoch(2, 21, 30, "different-head", epochs.get(2).tag());
        check("editing the chain head of a sealed epoch is rejected",
                fresh.verify("honeypot-01", edited) == ForwardSecureSeal.Result.BAD_TAG);

        ForwardSecureSeal.Verifier restored = new ForwardSecureSeal.Verifier(fresh.exportState());
        check("verifier state survives export/restore",
                restored.verify("honeypot-01", epochs.get(2)) == ForwardSecureSeal.Result.OK);
        check("skipping an epoch is reported as a gap",
                restored.verify("honeypot-01", epochs.get(5)) == ForwardSecureSeal.Result.EPOCH_GAP);
        sealer.close();
    }

    private static void payloadViews() {
        String once = "/admin?q=union%20select%20password";
        String twice = "/admin?q=union%2520select%2520password";
        String comment = "/admin?q=UN/**/ION/**/SELECT";
        check("single-encoded union select is visible", containsAny(PayloadViews.of(once, 3), "union select"));
        check("double-encoded union select is visible", containsAny(PayloadViews.of(twice, 3), "union select"));
        check("comment-obfuscated UNION SELECT is visible", containsAny(PayloadViews.of(comment, 3), "union select")
                || containsAny(PayloadViews.of(comment, 3), "unionselect"));
        check("benign text produces no SQL keyword", !containsAny(PayloadViews.of("/products?color=blue%20shirt", 3), "union select"));
        check("malformed encoding is flagged, not thrown", PayloadViews.of("/x?a=%zz", 3).malformedEncoding());
    }

    private static boolean containsAny(PayloadViews.Views views, String needle) {
        return views.texts().stream().anyMatch(t -> t.contains(needle));
    }

    private static void hybridKem() {
        try {
            for (HybridKem.Mode mode : HybridKem.Mode.values()) {
                HybridKem.ServerKeys keys = HybridKem.generate(mode);
                HybridKem.ClientResult client = HybridKem.encapsulate(mode,
                        keys.x25519() == null ? null : keys.x25519().getPublic(),
                        keys.mlKem() == null ? null : keys.mlKem().getPublic());
                byte[] server = HybridKem.decapsulate(mode, keys, client.offer());
                check("KEM mode " + mode + " both sides agree (" + client.offer().wireBytes() + " bytes on the wire)",
                        java.util.Arrays.equals(client.sharedSecret(), server));
            }
        } catch (Exception | LinkageError e) {
            check("hybrid KEM ran: " + e, false);
        }
    }

    private static void statistics() {
        double[] x = {10, 20, 30, 40, 50};
        check("nearest-rank p95 of 5 values is the maximum", Stats.percentile(x, 95) == 50);
        double[] ci = Stats.bootstrapMeanCi(x, 0.95, 2000, 1L);
        check("bootstrap CI brackets the mean", ci[0] <= 30 && ci[1] >= 30);
        double[] wilson = Stats.wilson(200, 200, 1.96);
        check("Wilson lower bound for 200/200 is below 1 but above 0.98", wilson[0] < 1 && wilson[0] > 0.98);
    }
}
