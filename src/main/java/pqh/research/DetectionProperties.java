package pqh.research;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "pqh.detection")
public record DetectionProperties(int maxDecodeRounds) {
  public DetectionProperties {
    if (maxDecodeRounds < 0) throw new IllegalArgumentException("maxDecodeRounds must be non-negative");
  }
}
