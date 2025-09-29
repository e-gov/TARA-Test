package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.hamcrest.MatcherAssert.assertThat
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
                        "groups", equalTo(Arrays.asList("liveness","readiness")),
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
        Response response

        if(endpoint == "health") response = Requests.getHealth(flow)
        else if ((endpoint == "health readiness")) response = Requests.getHealthReadiness(flow)
        else if ((endpoint == "health liveness")) response = Requests.getHealthLiveness(flow)

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
        when:
        Response response

        if(endpoint == "health") response = Requests.getRequest(flow, flow.loginService.healthUrl)
        else if ((endpoint == "health readiness")) response = Requests.getRequest(flow, flow.loginService.healthReadinessUrl)
        else if ((endpoint == "health liveness")) response = Requests.getRequest(flow, flow.loginService.healthLivenessUrl)

        then:
        assertThat("Correct status code", response.statusCode, is(404))
        assertThat("Correct path", response.jsonPath().getString("path"), is("/notfound"))

        where:
        endpoint           | _
        "health"           | _
        "health readiness" | _
        "health liveness"  | _
    }
}
