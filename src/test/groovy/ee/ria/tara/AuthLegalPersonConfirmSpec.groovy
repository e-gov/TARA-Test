package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.hamcrest.Matchers
import spock.lang.Ignore
import spock.lang.Unroll

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat

class AuthLegalPersonConfirmSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("LEGAL_PERSON_SELECTION_ENDPOINT")
    def "legal person selection request"() {
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

        Response legalPersonsResponse = Requests.followRedirectWithSessionId(flow, REQUEST_TYPE_GET, flow.loginService.fullAuthLegalPersonUrl)
        String legalPersonIdentifier = legalPersonsResponse.body().jsonPath().get("legalPersons[0].legalPersonIdentifier").toString()
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "legal_person_identifier", legalPersonIdentifier)
        HashMap<String, String> cookiesMap = (HashMap)Collections.emptyMap()
        def map2 = Utils.setParameter(cookiesMap, "SESSION", flow.sessionId)
        // TARA2-75 SESSION cookie in request?
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullAuthLegalConfirmUrl, cookiesMap, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        String location = response.getHeader("location")
        // TODO location contains <baasurl>/auth/accept ?
    }

    @Ignore // TARA2-75
    @Unroll
    @Feature("LEGAL_PERSON_SELECTION_ENDPOINT")
    def "legal person selection request with unsupported method get"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "legal_person_identifier", "123456789")
        Response response = Requests.getRequestWithParams(flow, flow.loginService.fullAuthLegalConfirmUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("Request method 'GET' not supported"))
    }

    @Unroll
    @Feature("LEGAL_PERSON_SELECTION_ENDPOINT")
    def "legal person selection request with no session and invalid parameter value"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "legal_person_identifier", "123456789")
        Response response = Requests.postRequestWithParams(flow, flow.loginService.fullAuthLegalConfirmUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        String message = "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo(message))
    }

    @Unroll
    @Feature("LEGAL_PERSON_SELECTION_ENDPOINT")
    def "legal person selection request with invalid parameter value"() {
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

        Response legalPersonsResponse = Requests.followRedirectWithSessionId(flow, REQUEST_TYPE_GET, flow.loginService.fullAuthLegalPersonUrl)
        String legalPersonIdentifier = legalPersonsResponse.body().jsonPath().get("legalPersons[0].legalPersonIdentifier").toString()
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "legal_person_identifier", "123456789")
        HashMap<String, String> cookiesMap = (HashMap)Collections.emptyMap()
        def map2 = Utils.setParameter(cookiesMap, "SESSION", flow.sessionId)
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullAuthLegalConfirmUrl, cookiesMap, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        // TARA2-75
        // assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("Ebakorrektne päring."))
    }

}
