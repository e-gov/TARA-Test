package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.commons.lang.RandomStringUtils
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
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 302, acceptResponse.statusCode())
        // /auth/legal_person/init
        Response initLegalResponse = Steps.followRedirectWithSessionId(flow, acceptResponse)
        assertEquals("Correct HTTP status code is returned", 200, initLegalResponse.statusCode())

        Response legalPersonsResponse = Requests.getRequestWithSessionId(flow, flow.loginService.fullAuthLegalPersonUrl)
        String legalPersonIdentifier = legalPersonsResponse.body().jsonPath().get("legalPersons[0].legalPersonIdentifier").toString()
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "legal_person_identifier", legalPersonIdentifier)
        def map3 = Utils.setParameter(paramsMap, "_csrf", flow.csrf)
        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(cookiesMap, "SESSION", flow.sessionId)
        // TARA2-75 SESSION cookie in request?
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullAuthLegalConfirmUrl, cookiesMap, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        String location = response.getHeader("location")
        assertThat(response.getHeader("location"), Matchers.containsString(flow.oidcService.fullAuthenticationRequestUrl))
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
    def "legal person selection request with invalid parameter value: #label"() {
        expect:
        Response initClientAuthenticationSession = Steps.initAuthenticationSession(flow, "openid legalperson")
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001019906", "00000766", Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, pollResponse.statusCode())
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 302, acceptResponse.statusCode())
        // /auth/legal_person/init
        Response initLegalResponse = Steps.followRedirectWithSessionId(flow, acceptResponse)
        assertEquals("Correct HTTP status code is returned", 200, initLegalResponse.statusCode())

        Response legalPersonsResponse = Requests.getRequestWithSessionId(flow, flow.loginService.fullAuthLegalPersonUrl)
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "legal_person_identifier", legalPersonIdentifier)
        def map3 = Utils.setParameter(paramsMap, "_csrf", flow.csrf)
        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(cookiesMap, "SESSION", flow.sessionId)
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullAuthLegalConfirmUrl, cookiesMap, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", statusCode, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo(errorMessage))

        where:
        legalPersonIdentifier                    | label                                            || statusCode || errorMessage
        // TARA2-75     "123456789"                              | "legal person identifier"             || 400        || "Ebakorrektne päring."
        RandomStringUtils.random(51, true, true) | "legal person identifier is too long"            || 400        || "confirmLegalPerson.legalPersonIdentifier: size must be between 0 and 50"
        "678@123"                                | "unsupported symbols in legal person identifier" || 400        || "confirmLegalPerson.legalPersonIdentifier: invalid legal person identifier"
        RandomStringUtils.random(50, true, true) | "legal person identifier"                        || 400        || "Ebakorrektne päring."
    }

}
