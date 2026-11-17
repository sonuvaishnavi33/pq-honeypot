package pqh.research;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "pqh.integrity")
public record IntegrityProperties(IntegrityMode mode, int epochSize, long sealIntervalMs,
                                  int checkpointEveryEpochs, String checkpointPrivateKey,
                                  String checkpointPublicKey, String checkpointPrivateKeyFile,
                                  String checkpointPublicKeyFile) {
  public IntegrityProperties {
    if (mode == null || epochSize < 1 || sealIntervalMs < 1 || checkpointEveryEpochs < 1) {
      throw new IllegalArgumentException("invalid integrity configuration");
    }
  }
}
