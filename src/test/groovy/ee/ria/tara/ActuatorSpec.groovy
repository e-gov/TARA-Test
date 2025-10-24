package ee.ria.tara

import ee.ria.tara.model.Actuator
import ee.ria.tara.util.ServiceUrls
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.http.HttpStatus
import spock.lang.Issue

import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.is

class ActuatorSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Feature("HEALTH_MONITORING_ENDPOINT")
    @Feature("HEALTH_MONITORING_ENDPOINT_DEPENDENCIES")
    @Feature("HEALTH_MONITORING_STATUS")
    def "Verify #service /actuator/prometheus response"() {
        when:
        Response response = Steps.getPrometheus(service.fullNodeUrl)

        then:
        response.then()
                .contentType("text/plain")
                .body(containsString("process_start_time_seconds"))

        where:
        service << [ServiceUrls.LOGIN_SERVICE, ServiceUrls.INPROXY_SERVICE, ServiceUrls.TARA_ADMIN_SERVICE, ServiceUrls.DEMO_CLIENT]
    }

    @Issue("AUT-2386")
    @Feature("HEALTH_MONITORING_ENDPOINT")
    @Feature("HEALTH_MONITORING_ENDPOINT_DEPENDENCIES")
    @Feature("HEALTH_MONITORING_STATUS")
    def "Verify #service actuator #endpoint dependent service '#component' status"() {
        expect:
        Steps.getActuatorEndpoint(service.fullNodeUrl, endpoint).then()
                .contentType("application/vnd.spring-boot.actuator")
                .body("components.${component}.status", equalTo("UP"))

        where:
        service                        | endpoint           | component
        ServiceUrls.LOGIN_SERVICE      | Actuator.HEALTH    | "ignite"
        ServiceUrls.LOGIN_SERVICE      | Actuator.HEALTH    | "oidcServer"
        ServiceUrls.LOGIN_SERVICE      | Actuator.READINESS | "oidcServer"

        // Issue: AUT-2386
//        ServiceUrls.INPROXY_SERVICE   | Actuator.HEALTH | "admin"

        ServiceUrls.TARA_ADMIN_SERVICE | Actuator.HEALTH    | "db"
        ServiceUrls.TARA_ADMIN_SERVICE | Actuator.HEALTH    | "ldap"
        ServiceUrls.TARA_ADMIN_SERVICE | Actuator.HEALTH    | "mail"
        ServiceUrls.TARA_ADMIN_SERVICE | Actuator.READINESS | "db"
        ServiceUrls.TARA_ADMIN_SERVICE | Actuator.READINESS | "ldap"
    }

    @Issue("AUT-2386")
    @Feature("HEALTH_MONITORING_ENDPOINT")
    @Feature("HEALTH_MONITORING_ENDPOINT_DEPENDENCIES")
    @Feature("HEALTH_MONITORING_STATUS")
    def "Verify #service actuator #endpoint status"() {
        expect:
        Steps.getActuatorEndpoint(service.fullNodeUrl, endpoint).then()
                .contentType("application/vnd.spring-boot.actuator")
                .body("status", is("UP"))

        where:
        service                        | endpoint
        ServiceUrls.LOGIN_SERVICE      | Actuator.HEALTH
        ServiceUrls.LOGIN_SERVICE      | Actuator.READINESS
        ServiceUrls.LOGIN_SERVICE      | Actuator.LIVENESS

        // Issue: AUT-2386
//        ServiceUrls.INPROXY_SERVICE   | Actuator.HEALTH
        ServiceUrls.INPROXY_SERVICE    | Actuator.READINESS
        ServiceUrls.INPROXY_SERVICE    | Actuator.LIVENESS

        ServiceUrls.TARA_ADMIN_SERVICE | Actuator.HEALTH
        ServiceUrls.TARA_ADMIN_SERVICE | Actuator.READINESS
        ServiceUrls.TARA_ADMIN_SERVICE | Actuator.LIVENESS

        ServiceUrls.DEMO_CLIENT        | Actuator.HEALTH
        ServiceUrls.DEMO_CLIENT        | Actuator.READINESS
        ServiceUrls.DEMO_CLIENT        | Actuator.LIVENESS
    }

    @Feature("HEALTH_MONITORING_ENDPOINT")
    def "#service actuator #endpoint cannot be accessed through proxy"() {
        expect:
        Steps.tryGetActuatorEndpoint(service.fullBaseUrl, endpoint).then()
                .statusCode(HttpStatus.SC_NOT_FOUND)
                .body("path", is("/notfound"))

        where:
        service                   | endpoint
        ServiceUrls.LOGIN_SERVICE | Actuator.HEALTH
        ServiceUrls.LOGIN_SERVICE | Actuator.READINESS
        ServiceUrls.LOGIN_SERVICE | Actuator.LIVENESS
        ServiceUrls.LOGIN_SERVICE | Actuator.PROMETHEUS
    }
}
