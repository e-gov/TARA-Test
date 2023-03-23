package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Unroll


import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo
import static org.junit.jupiter.api.Assertions.assertEquals

class LegalPersonAutInitSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Unroll
    @Feature("LEGAL_PERSON_INIT_START_ENDPOINT")
    @Feature("AUTH_REDIRECT_TO_LEGALPERSON_INIT")
    @Feature("OIDC_SCOPE_LEGALPERSON")
    def "request initialize legal person authentication"() {
        expect:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, "60001017705", "69000366", Collections.emptyMap())
        Steps.pollMidResponse(flow)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        Response response = Steps.followRedirectWithSessionId(flow, acceptResponse)

        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", response.getContentType(), "Correct content type")
        assertEquals("et", response.getHeader("Content-Language"), "Correct header attribute Content-Language")
        assertThat(response.body().htmlPath().get("**.find { it.@id == 'btn-select-legal-person'}").toString(), equalTo("Jätka"))
    }

    @Unroll
    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("SECURE_COOKIE_HANDLING")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "request initialize legal person authentication with security checks"() {
        expect:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Response response = Steps.authInitAsLegalPerson(flow, "60001017705", "69000366")

        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", response.getContentType(), "Correct content type")
        Steps.verifyResponseHeaders(response)
    }

    @Unroll
    @Feature("LEGAL_PERSON_INIT_START_ENDPOINT")
    def "request initialize legal person authentication with invalid session ID"() {
        expect:
        flow.setSessionId("1234567")
        Response response = Requests.getRequestWithSessionId(flow, flow.loginService.fullAuthLegalInitUrl)

        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertEquals("Teie seanssi ei leitud! Seanss aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"), "Correct error message is returned")
    }

    //TODO: AUT-630
    @Unroll
    @Feature("LEGAL_PERSON_INIT_START_ENDPOINT")
    def "request initialize legal person authentication with invalid method post"() {
        expect:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, "60001017705", "69000366", Collections.emptyMap())
        Steps.pollMidResponse(flow)
        Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)

        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthLegalInitUrl)
        assertEquals(500, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertThat(response.body().jsonPath().get("message").toString(), equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
    }
}
