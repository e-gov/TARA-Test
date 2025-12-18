package ee.ria.tara.model

enum Actuator {
    HEALTH("/actuator/health"),
    LIVENESS("/actuator/health/liveness"),
    READINESS("/actuator/health/readiness"),
    PROMETHEUS("/actuator/prometheus"),

    PROMETHEUS_OIDCSERVICE("/admin/metrics/prometheus"),
    LIVENESS_OIDCSERVICE("/health/alive"),
    READINESS_OIDCSERVICE("/health/ready"),

    final String endpoint

    Actuator(String endpoint) {
        this.endpoint = endpoint
    }

    String getEndpoint() {
        return endpoint
    }
}
