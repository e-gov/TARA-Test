package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import java.time.Duration

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.arrayContaining
import static org.hamcrest.Matchers.containsInAnyOrder
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.greaterThan
import static org.hamcrest.Matchers.hasEntry
import static org.hamcrest.Matchers.notNullValue
import static org.hamcrest.Matchers.is

class HeartBeatSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Feature("HEALTH_MONITORING_ENDPOINT")
    @Feature("HEALTH_MONITORING_ENDPOINT_DEPENDENCIES")
    @Feature("HEALTH_MONITORING_STATUS")
    def "Verify heartbeat response elements"() {
        when:
        Response heartBeat = Requests.getHeartbeat(flow)

        then:
        heartBeat.then().body(
                "status", is("UP"),
                "name", is("tara-login-server"),
                "version", notNullValue(),
                "commitId", notNullValue(),
                "commitBranch", notNullValue(),
                "buildTime", notNullValue(),
                "startTime", notNullValue(),
                "currentTime", notNullValue(),
                "upTime", notNullValue(),
                "dependencies.find { it.name == 'ignite' }.status", equalTo("UP"),
                "dependencies.find { it.name == 'oidcServer' }.status", equalTo("UP"),
                "dependencies.find { it.name == 'truststore' }.status", equalTo("UNKNOWN"))
                .contentType("application/json")
        String duration = heartBeat.jsonPath().get("upTime")
        Duration upTime = Duration.parse(duration)
        assertThat("Correct upTime value exists", upTime.seconds, greaterThan(5.toLong()))
    }

    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Verify heartbeat response headers"() {
        when:
        Response heartBeat = Requests.getHeartbeat(flow)

        then:
        Steps.verifyResponseHeaders(heartBeat)
    }

    @Feature("HEALTH_MONITORING_ENDPOINT")
    def "Heartbeat endpoint cannot be accessed through proxy"() {
        when:
        Response response = Requests.getRequest(flow, flow.loginService.heartbeatUrl)

        then:
        assertThat("Correct status code", response.statusCode, is(404))
        assertThat("Correct path", response.jsonPath().getString("path"), is("/notfound"))
    }
}
