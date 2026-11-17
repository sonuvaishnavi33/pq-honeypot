package pqh.research;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pqh.research.AttackMatrix.Row;

/**
 * Regression guard for the attack semantics. Runs against ReferenceTarget; point `target` at RealTarget to get the same
 * assertions on the real system (any difference is either a bug or an interesting finding: investigate, do not edit the test).
 */
class ExpectedMatrixTest {
    private final EvidenceTarget target = new ReferenceTarget();

    private double rate(IntegrityMode mode, String attackId) {
        List<Row> rows = AttackMatrix.run(Attacks.all(target, mode), 20, 7L);
        return rows.stream().filter(r -> r.attack().equals(attackId)).findFirst().orElseThrow().rate();
    }

    @Test @DisplayName("chain catches deletion, reordering and edits that transport encryption alone misses")
    void chainAddsDetection() {
        for (String id : List.of("A3_resend_old_events_fresh_counter", "A4_delete_event_in_batch", "A5_swap_two_events", "A6_edit_content_keep_hash")) {
            assertEquals(0.0, rate(IntegrityMode.NONE, id), id);
            assertEquals(1.0, rate(IntegrityMode.CHAIN, id), id);
        }
    }

    @Test @DisplayName("only the ratchet detects a rewrite of sealed backlog during a collector outage")
    void ratchetDetectsBacklogRewrite() {
        assertEquals(0.0, rate(IntegrityMode.CHAIN, "A10_backlog_rewrite_during_outage"));
        assertEquals(0.0, rate(IntegrityMode.CHAIN_ANCHOR, "A10_backlog_rewrite_during_outage"));
        assertEquals(1.0, rate(IntegrityMode.CHAIN_RATCHET, "A10_backlog_rewrite_during_outage"));
        assertEquals(1.0, rate(IntegrityMode.FULL, "A10_backlog_rewrite_during_outage"));
    }

    @Test @DisplayName("only signed checkpoints detect a consistent rewrite of the collector database")
    void anchorDetectsCollectorRewrite() {
        assertEquals(0.0, rate(IntegrityMode.CHAIN, "A12_collector_db_consistent_rewrite"));
        assertEquals(1.0, rate(IntegrityMode.CHAIN_ANCHOR, "A12_collector_db_consistent_rewrite"));
    }

    @Test @DisplayName("residual risk: nothing detects tail truncation or injection into the unsealed epoch")
    void residualRisk() {
        for (IntegrityMode mode : IntegrityMode.values()) {
            assertEquals(0.0, rate(mode, "A7_tail_truncation"), mode.name());
            assertEquals(0.0, rate(mode, "A11_inject_into_unsealed_epoch"), mode.name());
        }
    }
}
