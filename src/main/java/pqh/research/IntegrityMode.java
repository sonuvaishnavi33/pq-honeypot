package pqh.research;

/** Selects the evidence-integrity mechanisms enabled for a research run. */
public enum IntegrityMode {
  NONE(false, false, false),
  CHAIN(true, false, false),
  CHAIN_ANCHOR(true, true, false),
  CHAIN_RATCHET(true, false, true),
  FULL(true, true, true);

  public final boolean chain;
  public final boolean anchor;
  public final boolean ratchet;

  IntegrityMode(boolean chain, boolean anchor, boolean ratchet) {
    this.chain = chain;
    this.anchor = anchor;
    this.ratchet = ratchet;
  }
}
