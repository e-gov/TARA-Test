package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.commons.lang.RandomStringUtils
import org.hamcrest.Matchers
import spock.lang.Ignore
import spock.lang.Unroll

import static org.hamcrest.Matchers.equalTo
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat

class AuthConsentConfirmSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent with authentication results"() {
        expect:
        Response initResponse = Steps.authWithMobileID(flow)
        Response response = Steps.followRedirectWithSessionId(flow, initResponse)
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        assertThat(response.getHeader("location"), Matchers.startsWith(flow.oidcService.fullAuthenticationRequestUrl))
    }

    @Unroll
    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent with authentication results. Invalid session ID"() {
        expect:
        Response initResponse = Steps.authWithMobileID(flow)
        flow.setSessionId("1234567")
        Response response = Steps.followRedirectWithSessionId(flow, initResponse)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }

    @Ignore // TARA2-76
    @Unroll
    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent with authentication results. Invalid method post"() {
        expect:
        Response initResponse = Steps.authWithMobileID(flow)
        String location = initResponse.getHeader("location")
        Response response = Requests.followRedirectWithSessionId(flow, REQUEST_TYPE_POST, location)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), equalTo("Request method 'POST' not supported"))
    }

    @Ignore // TARA2-76
    @Unroll
    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent with authentication results. Missing session ID"() {
        expect:
        Response initResponse = Steps.authWithMobileID(flow)
        Response response = Steps.followRedirect(flow, initResponse)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }

    @Unroll
    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent with authentication results. Too long login_challenge"() {
        expect:
        Response initResponse = Steps.authWithMobileID(flow)
        String location = initResponse.getHeader("location")
        HashMap<String, String> cookiesMap = (HashMap)Collections.emptyMap()
        def map1 = Utils.setParameter(cookiesMap, "SESSION", flow.sessionId)
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "login_challenge", RandomStringUtils.random(51, true, true))
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullConsentUrl, cookiesMap, paramsMap, Collections.emptyMap())

        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), equalTo("Request method 'POST' not supported"))
    }



}
