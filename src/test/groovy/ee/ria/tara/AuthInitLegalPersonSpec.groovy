package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.hamcrest.Matchers
import spock.lang.Ignore
import spock.lang.Unroll

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat

class AuthInitLegalPersonSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("LEGAL_PERSON_INIT_START_ENDPOINT")
    @Feature("AUTH_REDIRECT_TO_LEGALPERSON_INIT")
    def "request initialize legal person authentication"() {
        expect:
        Response initClientAuthenticationSession = Steps.initAuthenticationSession(flow, "openid legalperson")
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001019906", "00000766", Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, pollResponse.statusCode())
        Response acceptResponse = Requests.followRedirectWithSessionId(flow, REQUEST_TYPE_POST, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 302, acceptResponse.statusCode())
        String oldSessionID = flow.sessionId
        // /auth/legal_person/init
        Response response = Steps.followRedirectWithSessionId(flow, acceptResponse)
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())
        assertEquals("Correct content type", "text/html;charset=UTF-8", response.getContentType())
        String sessionCookie = response.getCookie("SESSION")
        String sessionHeader = response.getHeader("Set-Cookie")
        assertEquals("Correct header attribute Content-Language", "et", response.getHeader("Content-Language"))
        // TARA2-75 new session cookie value
        // assertEquals("Correct header attribute Set-Cookie", "SESSION=${sessionCookie}; Path=/; Secure; HttpOnly; SameSite=Strict".toString(), sessionHeader)
    }

    @Unroll
    @Feature("LEGAL_PERSON_INIT_START_ENDPOINT")
    def "request initialize legal person authentication with invalid session ID"() {
        expect:
        flow.setSessionId("1234567")
        Response response = Requests.followRedirectWithSessionId(flow, REQUEST_TYPE_GET, flow.loginService.fullAuthLegalInitUrl)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }

    @Ignore // TARA2-80
    @Unroll
    @Feature("LEGAL_PERSON_INIT_START_ENDPOINT")
    def "request initialize legal person authentication with invalid method post"() {
        expect:
        flow.setSessionId("1234567")
        Response response = Requests.followRedirectWithSessionId(flow, REQUEST_TYPE_POST, flow.loginService.fullAuthLegalInitUrl)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("Request method 'POST' not supported"))
    }

    @Ignore //TARA2-75
    @Unroll
    @Feature("LEGAL_PERSON_INIT_START_ENDPOINT")
    def "request initialize legal person authentication with multiple session ID's"() {
        expect:
        Response initClientAuthenticationSession = Steps.initAuthenticationSession(flow, "openid legalperson")
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, pollResponse.statusCode())
        Response acceptResponse = Requests.followRedirectWithSessionId(flow, REQUEST_TYPE_POST, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 302, acceptResponse.statusCode())
        HashMap<String, String> cookiesMap = (HashMap)Collections.emptyMap()
        def map1 = Utils.setParameter(cookiesMap, "SESSION", "S12345")
        Response response = Requests.followRedirectWithSessionIdAndCookies(flow, REQUEST_TYPE_GET, flow.loginService.fullAuthLegalInitUrl, cookiesMap)
        // assertEquals("Correct HTTP status code is returned", 400, response.statusCode())

        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }
}
