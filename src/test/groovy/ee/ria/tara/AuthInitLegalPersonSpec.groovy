package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.hamcrest.Matchers
import spock.lang.Ignore
import spock.lang.IgnoreIf
import spock.lang.Unroll

import static org.hamcrest.Matchers.equalTo
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat

@IgnoreIf({ properties['test.deployment.env'] != "idp" })
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
        Steps.startAuthenticationInTara(flow, "openid legalperson")
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017705", "69000366", Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, pollResponse.statusCode())
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 302, acceptResponse.statusCode())
        assertThat(acceptResponse.getHeader("location"), Matchers.containsString(flow.loginService.authLegalInitUrl))

        Response response = Steps.followRedirectWithSessionId(flow, acceptResponse)
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())
        assertEquals("Correct content type", "text/html;charset=UTF-8", response.getContentType())
        assertEquals("Correct header attribute Content-Language", "et", response.getHeader("Content-Language"))
        assertThat(response.body().htmlPath().get("**.find { it.@id == 'btn-select-legal-person'}").toString(), equalTo("Jätkan"))
    }

    @Unroll
    @Feature("LEGAL_PERSON_INIT_START_ENDPOINT")
    def "request initialize legal person authentication with invalid session ID"() {
        expect:
        flow.setSessionId("1234567")
        Response response = Requests.getRequestWithSessionId(flow, flow.loginService.fullAuthLegalInitUrl)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }

    @Ignore // TARA2-80 TARA2-165
    @Unroll
    @Feature("LEGAL_PERSON_INIT_START_ENDPOINT")
    def "request initialize legal person authentication with invalid method post"() {
        expect:
        flow.setSessionId("1234567")
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthLegalInitUrl)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), equalTo("Request method 'POST' not supported"))
    }

}
