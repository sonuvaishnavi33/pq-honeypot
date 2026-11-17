package pqh.research;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Seeded attack matrix that separates errors and non-applicable cases from detections. */
public final class AttackMatrix {
  public static final String NOT_APPLICABLE = "NOT_APPLICABLE";

  private AttackMatrix() {}

  public record Outcome(boolean detected, String verdict, long exposedEvents) {
    public static Outcome notApplicable() { return new Outcome(false, NOT_APPLICABLE, 0); }
  }

  public interface Attack {
    String id();
    String description();
    Outcome run(long seed) throws Exception;
  }

  public record Row(String attack, int trials, int detected, double rate, double wilsonLow,
                    double wilsonHigh, double meanExposedEvents, int errors, int notApplicable) {}

  public static List<Row> run(List<Attack> attacks, int trials, long baseSeed) {
    if (trials < 1) throw new IllegalArgumentException("trials must be positive");
    List<Row> rows = new ArrayList<>();
    for (Attack attack : attacks) {
      int detected = 0, errors = 0, notApplicable = 0;
      double exposed = 0;
      for (int trial = 0; trial < trials; trial++) {
        try {
          Outcome outcome = attack.run(baseSeed + trial);
          if (NOT_APPLICABLE.equals(outcome.verdict())) {
            notApplicable++;
            continue;
          }
          if (outcome.detected()) detected++;
          exposed += outcome.exposedEvents();
        } catch (Exception ex) {
          errors++;
          System.err.printf("Attack trial failed: attack=%s trial=%d seed=%d error=%s%n",
              attack.id(), trial + 1, baseSeed + trial, ex);
        }
      }
      int valid = trials - errors - notApplicable;
      double[] interval = Stats.wilson(detected, valid, 1.96);
      rows.add(new Row(attack.id(), valid, detected, valid == 0 ? Double.NaN : (double) detected / valid,
          interval[0], interval[1], valid == 0 ? Double.NaN : exposed / valid, errors, notApplicable));
    }
    return List.copyOf(rows);
  }

  public static String toCsv(String target, String integrityMode, List<Row> rows) {
    StringBuilder csv = new StringBuilder(
        "target,mode,attack,trials,detected,rate,wilson_low,wilson_high,mean_exposed_events,errors,not_applicable\n");
    for (Row row : rows) {
      csv.append(String.format(Locale.ROOT, "%s,%s,%s,%d,%d,%.4f,%.4f,%.4f,%.2f,%d,%d%n",
          target, integrityMode, row.attack(), row.trials(), row.detected(), row.rate(), row.wilsonLow(),
          row.wilsonHigh(), row.meanExposedEvents(), row.errors(), row.notApplicable()));
    }
    return csv.toString();
  }
}
