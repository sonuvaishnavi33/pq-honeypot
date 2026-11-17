package pqh.research;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "pqh.kem")
public record KemProperties(HybridKem.Mode mode) {
  public KemProperties {
    if (mode == null) throw new IllegalArgumentException("pqh.kem.mode is required");
  }
}
