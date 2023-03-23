package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Unroll

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo
import static org.junit.jupiter.api.Assertions.assertEquals
import static org.junit.jupiter.api.Assertions.assertTrue

class LegalPersonAuthSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Unroll
    @Feature("LEGAL_PERSON_AUTH_START_ENDPOINT")
    def "legal persons authentication request"() {
        expect:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.authInitAsLegalPerson(flow, "60001019906", "00000766")
        Response response = Steps.loadLegalPersonsList(flow)
        // TODO: better environment selection solution here
        List<String> legalPersonIdentifiers = response.body().jsonPath().getList("legalPersons.legalPersonIdentifier")
        List<String> legalPersonNames = response.body().jsonPath().getList("legalPersons.legalName")

        if(flow.loginService.baseUrl.contains("service-backend")) { //local environment
            assertTrue(legalPersonNames.contains("Acme INC OÜ"))
            assertTrue(legalPersonIdentifiers.contains("12341234"))
        }  else {
            // other environments
            assertTrue(legalPersonNames.contains("täisühing VAVILOV") || legalPersonNames.contains("AS Hallebygg"))
            assertTrue(legalPersonIdentifiers.contains("10910878") || legalPersonIdentifiers.contains("12597552"))
        }
    }

    @Unroll
    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("SECURE_COOKIE_HANDLING")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "legal persons authentication request with security checks"() {
        expect:
        Steps.startAuthenticationInTaraWithLegalPerson(flow, "openid legalperson")
        Steps.authInitAsLegalPerson(flow, "60001019906", "00000766")
        Response response = Steps.loadLegalPersonsList(flow)

        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        Steps.verifyResponseHeaders(response)
    }

    @Unroll
    @Feature("LEGAL_PERSON_AUTH_START_ENDPOINT")
    def "legal persons authentication request with invalid session ID"() {
        expect:
        flow.setSessionId("1234567")
        Response response = Requests.getRequestWithSessionId(flow, flow.loginService.fullAuthLegalPersonUrl)

        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertEquals("Teie seanssi ei leitud! Seanss aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"), "Correct error message is returned")
    }

    //TODO: AUT-630
    @Unroll
    @Feature("LEGAL_PERSON_AUTH_START_ENDPOINT")
    def "legal persons authentication request with invalid method post"() {
        expect:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, "60001019906", "00000766", Collections.emptyMap())
        Steps.pollMidResponse(flow)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        Steps.followRedirectWithSessionId(flow, acceptResponse)
        HashMap<String, String> cookiesMap = (HashMap)Collections.emptyMap()
        def map2 = Utils.setParameter(cookiesMap, "SESSION",flow.sessionId)
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "_csrf", flow.csrf)
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullAuthLegalPersonUrl, cookiesMap, formParamsMap, Collections.emptyMap())

        assertEquals(500, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertThat(response.body().jsonPath().get("message").toString(), equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
    }
}
