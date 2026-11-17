package pqh.crypto;

import java.util.List;
import pqh.research.CheckpointSigner;
import pqh.research.ForwardSecureSeal;

/** JSON payload encrypted and forwarded from the source to the collector. */
public record EvidenceBatch(List<Ev.Rec> records, List<ForwardSecureSeal.Epoch> seals,
                            List<CheckpointSigner.Checkpoint> checkpoints) {
  public EvidenceBatch {
    records = List.copyOf(records);
    seals = List.copyOf(seals);
    checkpoints = List.copyOf(checkpoints);
  }
}
