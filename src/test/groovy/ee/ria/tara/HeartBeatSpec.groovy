package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Ignore
import spock.lang.Unroll
import org.hamcrest.Matchers
import org.apache.commons.lang.RandomStringUtils

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat

class HeartBeatSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }


    @Unroll
    @Feature("HEALTH_MONITORING_ENDPOINTT")
    @Feature("HEALTH_MONITORING_ENDPOINT_DEPENDENCIES")
    def "Verify heartbeat response elements"() {
        expect:
        Response heartBeat = Requests.getHeartbeat(flow)
        heartBeat.then()
                .body("status", Matchers.notNullValue())
                .body("name", Matchers.notNullValue())
                .body("version", Matchers.notNullValue())
                .body("commitId", Matchers.notNullValue())
                .body("commitBranch", Matchers.notNullValue())
                .body("buildTime", Matchers.notNullValue())
                .body("startTime", Matchers.notNullValue())
                .body("currentTime", Matchers.notNullValue())
                .body("upTime", Matchers.notNullValue())
                .body("dependencies[0].name", Matchers.is("oidcServer"))
                .body("dependencies[0].status", Matchers.is("UP"))
                .body("dependencies[1].name", Matchers.is("hazelcast"))
                .body("dependencies[1].status", Matchers.is("UP"))
                .body("dependencies[2].name", Matchers.is("truststore"))
                .body("dependencies[2].status", Matchers.is("UP"))
                .contentType("application/json")
    }
}
