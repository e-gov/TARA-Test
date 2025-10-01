package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.notNullValue

class ActuatorHealthSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Feature("HEALTH_MONITORING_ENDPOINT")
    @Feature("HEALTH_MONITORING_ENDPOINT_DEPENDENCIES")
    @Feature("HEALTH_MONITORING_STATUS")
    def "Verify 'health' response elements"() {
        when:
        Response response = Requests.getHealth(flow)

        then:
        response.then()
                .contentType("application/vnd.spring-boot.actuator.v3+json")
                .body(
                        "status", is("UP"),
                        "groups", equalTo(Arrays.asList("liveness", "readiness")),
                        "components.ignite.status", equalTo("UP"),
                        "components.livenessState.status", equalTo("UP"),
                        "components.oidcServer.status", equalTo("UP"),
                        "components.readinessState.status", equalTo("UP"),
                        "components.truststore.status", equalTo("UP"),
                        "components.truststore.details", notNullValue()
                )
    }

    @Feature("HEALTH_MONITORING_ENDPOINT")
    @Feature("HEALTH_MONITORING_ENDPOINT_DEPENDENCIES")
    @Feature("HEALTH_MONITORING_STATUS")
    def "Verify 'health readiness' response elements"() {
        when:
        Response response = Requests.getHealthReadiness(flow)

        then:
        response.then()
                .contentType("application/vnd.spring-boot.actuator.v3+json")
                .body(
                        "status", is("UP"),
                        "components.oidcServer.status", equalTo("UP"),
                        "components.readinessState.status", equalTo("UP"),
                )
    }

    @Feature("HEALTH_MONITORING_ENDPOINT")
    @Feature("HEALTH_MONITORING_ENDPOINT_DEPENDENCIES")
    @Feature("HEALTH_MONITORING_STATUS")
    def "Verify 'health liveness' response elements"() {
        when:
        Response response = Requests.getHealthLiveness(flow)

        then:
        response.then()
                .contentType("application/vnd.spring-boot.actuator.v3+json")
                .body(
                        "status", is("UP"))
    }

    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Verify '#endpoint' response headers"() {
        when:
        Response response = switch (endpoint) {
            case "health" -> Requests.getHealth(flow)
            case "health readiness" -> Requests.getHealthReadiness(flow)
            case "health liveness" -> Requests.getHealthLiveness(flow)
            default -> throw new Exception("Unknown endpoint: $endpoint")
        }

        then:
        Steps.verifyResponseHeaders(response)

        where:
        endpoint           | _
        "health"           | _
        "health readiness" | _
        "health liveness"  | _
    }

    @Feature("HEALTH_MONITORING_ENDPOINT")
    def "Endpoint '#endpoint' cannot be accessed through proxy"() {
        given:
        String url = switch (endpoint) {
            case "health" -> flow.loginService.healthUrl
            case "health readiness" -> flow.loginService.healthReadinessUrl
            case "health liveness" -> flow.loginService.healthLivenessUrl
            default -> throw new Exception("Unknown endpoint: $endpoint")
        }

        when:
        Response response = Requests.getRequest(flow, url)

        then:
        response.then()
                .statusCode(404)
                .body("path", is("/notfound"))

        where:
        endpoint           | _
        "health"           | _
        "health readiness" | _
        "health liveness"  | _
    }
}
