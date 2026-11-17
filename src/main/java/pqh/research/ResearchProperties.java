package pqh.research;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "pqh.research")
public record ResearchProperties(int trials, long seed, String outputDir, Exposure exposure,
                                 Benchmark benchmark) {
  public ResearchProperties {
    if (trials < 1) throw new IllegalArgumentException("trials must be positive");
    if (outputDir == null || outputDir.isBlank()) throw new IllegalArgumentException("outputDir required");
  }

  public record Exposure(int trials, int bootstrapResamples, List<Integer> epochSizes,
                         List<Long> sealIntervalsMs, List<Double> ratesPerSecond) {
    public Exposure {
      epochSizes = List.copyOf(epochSizes);
      sealIntervalsMs = List.copyOf(sealIntervalsMs);
      ratesPerSecond = List.copyOf(ratesPerSecond);
      if (trials < 1 || bootstrapResamples < 1) {
        throw new IllegalArgumentException("exposure trial and resample counts must be positive");
      }
    }
  }

  public record Benchmark(int runs, int iterationsPerRun, int warmup, int bootstrapResamples,
                          List<Integer> concurrentClients, List<Integer> batchSizes) {
    public Benchmark {
      concurrentClients = List.copyOf(concurrentClients);
      batchSizes = List.copyOf(batchSizes);
      if (runs < 1 || iterationsPerRun < 1 || warmup < 0 || bootstrapResamples < 1) {
        throw new IllegalArgumentException("invalid benchmark configuration");
      }
    }
  }
}
