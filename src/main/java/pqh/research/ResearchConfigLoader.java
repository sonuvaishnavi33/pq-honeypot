package pqh.research;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Configuration;

/** Loads research settings from application.yml plus Spring environment overrides. */
public final class ResearchConfigLoader {
  private ResearchConfigLoader() {}

  public record Settings(ResearchProperties research, IntegrityProperties integrity,
                         KemProperties kem, DetectionProperties detection) {}

  public static Settings load() {
    try (ConfigurableApplicationContext context = new SpringApplicationBuilder(PropertiesOnly.class)
        .web(WebApplicationType.NONE).run()) {
      return new Settings(context.getBean(ResearchProperties.class),
          context.getBean(IntegrityProperties.class), context.getBean(KemProperties.class),
          context.getBean(DetectionProperties.class));
    }
  }

  @Configuration(proxyBeanMethods = false)
  @EnableConfigurationProperties({ResearchProperties.class, IntegrityProperties.class,
      KemProperties.class, DetectionProperties.class})
  static class PropertiesOnly {}
}
