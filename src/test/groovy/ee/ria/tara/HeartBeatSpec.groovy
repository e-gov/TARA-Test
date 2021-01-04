package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Unroll
import org.hamcrest.Matchers

import java.time.Duration
import static org.junit.Assert.assertTrue

class HeartBeatSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }


    @Unroll
    @Feature("HEALTH_MONITORING_ENDPOINT")
    @Feature("HEALTH_MONITORING_ENDPOINT_DEPENDENCIES")
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
                .body("dependencies[0].name", Matchers.is("oidcServer"))
                .body("dependencies[0].status", Matchers.oneOf("UP", "DOWN"))
                .body("dependencies[1].name", Matchers.is("truststore"))
                .body("dependencies[1].status",  Matchers.oneOf("UP", "DOWN"))
        //        .body("dependencies[2].name", Matchers.is("ignite"))
        //        .body("dependencies[2].status",  Matchers.oneOf("UP", "DOWN"))
                .contentType("application/json")
        String duration = heartBeat.body().jsonPath().get("upTime")
        Duration upTime = Duration.parse(duration)
        assertTrue("Correct upTime value exists", upTime.getSeconds() > 5)
    }
}
