package pqh.research;

import java.util.Arrays;
import java.util.Random;

/** Descriptive statistics used by the research runners. */
public final class Stats {
  private Stats() {}

  public static double mean(double[] values) {
    if (values.length == 0) return Double.NaN;
    double sum = 0;
    for (double value : values) sum += value;
    return sum / values.length;
  }

  public static double stdev(double[] values) {
    if (values.length < 2) return 0;
    double avg = mean(values), sum = 0;
    for (double value : values) sum += (value - avg) * (value - avg);
    return Math.sqrt(sum / (values.length - 1));
  }

  public static double percentile(double[] values, double percentile) {
    if (values.length == 0) throw new IllegalArgumentException("values must not be empty");
    if (!(percentile > 0 && percentile <= 100)) throw new IllegalArgumentException("percentile must be in (0,100]");
    double[] sorted = values.clone();
    Arrays.sort(sorted);
    int rank = (int) Math.ceil(percentile / 100.0 * sorted.length);
    return sorted[Math.max(1, rank) - 1];
  }

  public static double[] bootstrapMeanCi(double[] values, double confidence, int resamples, long seed) {
    if (values.length == 0 || resamples < 1 || !(confidence > 0 && confidence < 1)) {
      throw new IllegalArgumentException("non-empty data, positive resamples, and confidence in (0,1) required");
    }
    Random random = new Random(seed);
    double[] means = new double[resamples];
    for (int r = 0; r < resamples; r++) {
      double sum = 0;
      for (int i = 0; i < values.length; i++) sum += values[random.nextInt(values.length)];
      means[r] = sum / values.length;
    }
    Arrays.sort(means);
    double alpha = 1 - confidence;
    return new double[] {
        means[(int) Math.floor(alpha / 2 * resamples)],
        means[(int) Math.min(resamples - 1, Math.ceil((1 - alpha / 2) * resamples) - 1)]};
  }

  public static double[] wilson(int successes, int trials, double z) {
    if (trials < 0 || successes < 0 || successes > trials || !(z > 0)) {
      throw new IllegalArgumentException("invalid binomial observations");
    }
    if (trials == 0) return new double[] {Double.NaN, Double.NaN};
    double p = (double) successes / trials, z2 = z * z;
    double center = (p + z2 / (2 * trials)) / (1 + z2 / trials);
    double half = z * Math.sqrt(p * (1 - p) / trials + z2 / (4.0 * trials * trials))
        / (1 + z2 / trials);
    return new double[] {Math.max(0, center - half), Math.min(1, center + half)};
  }
}
