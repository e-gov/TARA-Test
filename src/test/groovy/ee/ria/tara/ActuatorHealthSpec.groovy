package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.is

class ActuatorHealthSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Feature("HEALTH_MONITORING_ENDPOINT")
    @Feature("HEALTH_MONITORING_ENDPOINT_DEPENDENCIES")
    @Feature("HEALTH_MONITORING_STATUS")
    def "Verify health response elements"() {
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

                        "components.truststore.details.esteid2018.validTo", equalTo("2033-09-05T09:11:03Z"),
                        "components.truststore.details.esteid2018.subjectDN",
                        equalTo("CN=ESTEID2018, OID.2.5.4.97=NTREE-10747013, O=SK ID Solutions AS, C=EE"),
                        "components.truststore.details.esteid2018.serialNumber",
                        equalTo("155893412819766287602132218565978641901"),

                        "components.truststore.details.test_esteid2025.validTo", equalTo("2039-11-03T12:59:54Z"),
                        "components.truststore.details.test_esteid2025.subjectDN",
                        equalTo("C=EE, O=Zetes Estonia OÜ, OID.2.5.4.97=NTREE-17066049, CN=Test ESTEID2025"),
                        "components.truststore.details.test_esteid2025.serialNumber",
                        equalTo("313056598907719234537539868393943821635307528921"),

                        "components.truststore.details.test_of_esteid2018.validTo", equalTo("2033-08-30T12:48:28Z"),
                        "components.truststore.details.test_of_esteid2018.subjectDN",
                        equalTo("CN=TEST of ESTEID2018, OID.2.5.4.97=NTREE-10747013, O=SK ID Solutions AS, C=EE"),
                        "components.truststore.details.test_of_esteid2018.serialNumber",
                        equalTo("71907861382765673730662460475615088197"),

                        "components.truststore.details.demo_of_klass3_sk_2016_ssl_ocsp_responder_2018.validTo",
                        equalTo("2030-12-17T05:30:32Z"),
                        "components.truststore.details.demo_of_klass3_sk_2016_ssl_ocsp_responder_2018.subjectDN",
                        equalTo("C=EE, O=SK ID Solutions AS, OU=OCSP, CN=DEMO of KLASS3-SK 2016 SSL OCSP RESPONDER 2018"),
                        "components.truststore.details.demo_of_klass3_sk_2016_ssl_ocsp_responder_2018.serialNumber",
                        equalTo("44706571542661122683924256357413590830"),
                )
    }

    @Feature("HEALTH_MONITORING_ENDPOINT")
    @Feature("HEALTH_MONITORING_ENDPOINT_DEPENDENCIES")
    @Feature("HEALTH_MONITORING_STATUS")
    def "Verify health readiness response elements"() {
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
    def "Verify health liveness response elements"() {
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
    def "Verify health response headers"() {
        when:
        Response response = Requests.getHealth(flow)

        then:
        Steps.verifyResponseHeaders(response)
    }

    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Verify health readiness response headers"() {
        when:
        Response response = Requests.getHealthReadiness(flow)

        then:
        Steps.verifyResponseHeaders(response)
    }

    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Verify health liveness response headers"() {
        when:
        Response response = Requests.getHealthLiveness(flow)

        then:
        Steps.verifyResponseHeaders(response)
    }

    @Feature("HEALTH_MONITORING_ENDPOINT")
    def "Health endpoint cannot be accessed through proxy"() {
        when:
        Response response = Requests.getRequest(flow, flow.loginService.healthUrl)

        then:
        assertThat("Correct status code", response.statusCode, is(404))
        assertThat("Correct path", response.jsonPath().getString("path"), is("/notfound"))
    }

    @Feature("HEALTH_MONITORING_ENDPOINT")
    def "Health readiness endpoint cannot be accessed through proxy"() {
        when:
        Response response = Requests.getRequest(flow, flow.loginService.healthReadinessUrl)

        then:
        assertThat("Correct status code", response.statusCode, is(404))
        assertThat("Correct path", response.jsonPath().getString("path"), is("/notfound"))
    }

    @Feature("HEALTH_MONITORING_ENDPOINT")
    def "Health liveness endpoint cannot be accessed through proxy"() {
        when:
        Response response = Requests.getRequest(flow, flow.loginService.healthLivenessUrl)

        then:
        assertThat("Correct status code", response.statusCode, is(404))
        assertThat("Correct path", response.jsonPath().getString("path"), is("/notfound"))
    }
}
