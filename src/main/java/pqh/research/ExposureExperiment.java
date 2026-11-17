package pqh.research;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Random;

/**
 * Exposure window = events logged but not yet sealed when the attacker takes over (they remain forgeable).
 * Sweeps the configured epoch sizes, seal intervals and event rates with Poisson arrivals.
 */
public final class ExposureExperiment {
    public static void main(String[] args) throws IOException {
        ResearchProperties properties = ResearchConfigLoader.load().research();
        int trials = args.length > 0 ? Integer.parseInt(args[0]) : properties.exposure().trials();
        long seed = args.length > 1 ? Long.parseLong(args[1]) : properties.seed();
        Path out = Path.of(args.length > 2 ? args[2]
                : properties.outputDir() + "/exposure_tradeoff_model.csv");
        int bootstrapResamples = properties.exposure().bootstrapResamples();

        StringBuilder csv = new StringBuilder("epoch_size,seal_interval_ms,rate_per_s,trials,mean_exposed,ci95_low,ci95_high,p95_exposed,max_exposed\n");
        StringBuilder samplesCsv = new StringBuilder(
                "epoch_size,seal_interval_ms,rate_per_s,trial,exposed_events,seed\n");
        for (int epochSize : properties.exposure().epochSizes()) {
            for (long intervalMs : properties.exposure().sealIntervalsMs()) {
                for (double rate : properties.exposure().ratesPerSecond()) {
                    double[] exposed = new double[trials];
                    long conditionSeed = seed ^ (epochSize * 31L + intervalMs * 17L + (long) rate);
                    Random random = new Random(conditionSeed);
                    for (int t = 0; t < trials; t++) {
                        exposed[t] = exposedAt(random, epochSize, intervalMs / 1000.0, rate);
                        samplesCsv.append(String.format(Locale.ROOT, "%d,%d,%.1f,%d,%.0f,%d%n",
                                epochSize, intervalMs, rate, t + 1, exposed[t], conditionSeed));
                    }
                    double[] ci = Stats.bootstrapMeanCi(exposed, 0.95, bootstrapResamples, conditionSeed);
                    double max = 0;
                    for (double v : exposed) max = Math.max(max, v);
                    csv.append(String.format(Locale.ROOT, "%d,%d,%.1f,%d,%.3f,%.3f,%.3f,%.1f,%.0f%n", epochSize, intervalMs, rate, trials,
                            Stats.mean(exposed), ci[0], ci[1], Stats.percentile(exposed, 95), max));
                }
            }
        }
        if (out.getParent() != null) Files.createDirectories(out.getParent());
        Files.writeString(out, csv.toString());
        String samplesFile = out.getFileName().toString().replace(".csv", "_samples.csv");
        Files.writeString(out.resolveSibling(samplesFile), samplesCsv.toString());
        System.out.println(csv);
        System.out.println("Summary CSV: " + out.toAbsolutePath());
        System.out.println("Raw samples CSV: " + out.resolveSibling(samplesFile).toAbsolutePath());
    }

    /** One random compromise moment: how many events are unsealed right then? */
    static double exposedAt(Random random, int epochSize, double sealIntervalSeconds, double ratePerSecond) {
        double compromiseAt = 20 + random.nextDouble() * 20;
        double time = 0, firstUnsealed = 0;
        int unsealed = 0;
        while (true) {
            time += -Math.log(1 - random.nextDouble()) / ratePerSecond;           // Poisson arrivals
            if (unsealed > 0 && Math.min(time, compromiseAt) >= firstUnsealed + sealIntervalSeconds) unsealed = 0;   // timer seal
            if (time > compromiseAt) return unsealed;
            if (unsealed == 0) firstUnsealed = time;
            if (++unsealed >= epochSize) unsealed = 0;                           // size seal
        }
    }
}
