package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Unroll
import org.hamcrest.Matchers

import java.time.Duration

import static org.junit.jupiter.api.Assertions.*

class HeartBeatSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }


    @Unroll
    @Feature("HEALTH_MONITORING_ENDPOINT")
    @Feature("HEALTH_MONITORING_ENDPOINT_DEPENDENCIES")
    @Feature("HEALTH_MONITORING_STATUS")
    def "Verify heartbeat response elements"() {
        expect:
        Response heartBeat = Requests.getHeartbeat(flow)
        heartBeat.then()
                .body("status", Matchers.oneOf("UP", "DOWN"))
                .body("name", Matchers.equalTo("tara-login-server"))
                .body("version", Matchers.notNullValue())
                .body("commitId", Matchers.notNullValue())
                .body("commitBranch", Matchers.notNullValue())
                .body("buildTime", Matchers.notNullValue())
                .body("startTime", Matchers.notNullValue())
                .body("currentTime", Matchers.notNullValue())
                .body("upTime", Matchers.notNullValue())
                .body("dependencies[0].name", Matchers.is("ignite"))
                .body("dependencies[0].status", Matchers.oneOf("UP", "DOWN", "UNKNOWN"))
                .body("dependencies[1].name", Matchers.is("oidcServer"))
                .body("dependencies[1].status", Matchers.oneOf("UP", "DOWN", "UNKNOWN"))
                .body("dependencies[2].name", Matchers.is("truststore"))
                .body("dependencies[2].status",  Matchers.oneOf("UP", "DOWN", "UNKNOWN"))
                .contentType("application/json")
        String duration = heartBeat.body().jsonPath().get("upTime")
        Duration upTime = Duration.parse(duration)
        assertTrue(upTime.getSeconds() > 5, "Correct upTime value exists")
        String serviceStatus = heartBeat.body().jsonPath().get("status")
        switch (serviceStatus) {
            case "UP" :
                assertEquals(200, heartBeat.statusCode(), "Correct heartbeat HTTP status code is returned")
                break
            case "DOWN" :
                assertEquals(503, heartBeat.statusCode(), "Correct heartbeat HTTP status code is returned if some component is down")
                break
        }
    }

    @Unroll
    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Verify heartbeat response headers"() {
        expect:
        Response heartBeat = Requests.getHeartbeat(flow)
        Steps.verifyResponseHeaders(heartBeat)
    }
}
