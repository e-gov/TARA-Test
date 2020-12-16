package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.hamcrest.Matchers
import spock.lang.Ignore
import spock.lang.Unroll

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat

class AuthLegalPersonSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("LEGAL_PERSON_AUTH_START_ENDPOINT")
    def "legal persons authentication request"() {
        expect:
        Response initClientAuthenticationSession = Steps.initAuthenticationSession(flow, "openid legalperson")
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001019906", "00000766", Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, pollResponse.statusCode())
        Response acceptResponse = Requests.followRedirectWithSessionId(flow, REQUEST_TYPE_POST, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 302, acceptResponse.statusCode())
        // /auth/legal_person/init
        Response initLegalResponse = Steps.followRedirectWithSessionId(flow, acceptResponse)
        assertEquals("Correct HTTP status code is returned", 200, initLegalResponse.statusCode())
        Response response = Requests.followRedirectWithSessionId(flow, REQUEST_TYPE_GET, flow.loginService.fullAuthLegalPersonUrl)
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertThat(response.body().jsonPath().get("legalPersons[0].legalPersonIdentifier").toString(), Matchers.equalTo("12341234"))
        assertThat(response.body().jsonPath().get("legalPersons[0].legalName").toString(), Matchers.equalTo("Acme INC OÜ"))
    }

    @Unroll
    @Feature("LEGAL_PERSON_AUTH_START_ENDPOINT")
    def "legal persons authentication request with invalid session ID"() {
        expect:
        flow.setSessionId("1234567")
        Response response = Requests.followRedirectWithSessionId(flow, REQUEST_TYPE_GET, flow.loginService.fullAuthLegalPersonUrl)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }

    @Ignore // TARA2-80
    @Unroll
    @Feature("LEGAL_PERSON_AUTH_START_ENDPOINT")
    def "legal persons authentication request with invalid method post"() {
        expect:
        flow.setSessionId("1234567")
        Response response = Requests.followRedirectWithSessionId(flow, REQUEST_TYPE_POST, flow.loginService.fullAuthLegalPersonUrl)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("Request method 'POST' not supported"))
    }

    @Ignore //TARA2-75
    @Unroll
    @Feature("LEGAL_PERSON_AUTH_START_ENDPOINT")
    def "legal persons authentication request with multiple session ID's"() {
        expect:
        Response initClientAuthenticationSession = Steps.initAuthenticationSession(flow, "openid legalperson")
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001019906", "00000766", Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, pollResponse.statusCode())
        Response acceptResponse = Requests.followRedirectWithSessionId(flow, REQUEST_TYPE_POST, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 302, acceptResponse.statusCode())
        // /auth/legal_person/init
        Response initLegalResponse = Steps.followRedirectWithSessionId(flow, acceptResponse)
        HashMap<String, String> cookiesMap = (HashMap)Collections.emptyMap()
        def map1 = Utils.setParameter(cookiesMap, "SESSION", "S12345")
        Response response = Requests.followRedirectWithSessionIdAndCookies(flow, REQUEST_TYPE_GET, flow.loginService.fullAuthLegalPersonUrl, cookiesMap)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())

        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }
}
