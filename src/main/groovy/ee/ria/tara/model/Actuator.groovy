package ee.ria.tara.model

enum Actuator {
    HEALTH("/actuator/health"),
    LIVENESS("/actuator/health/liveness"),
    READINESS("/actuator/health/readiness"),
    PROMETHEUS("/actuator/prometheus"),

    final String endpoint

    Actuator(String endpoint) {
        this.endpoint = endpoint
    }

    String getEndpoint() {
        return endpoint
    }
}
