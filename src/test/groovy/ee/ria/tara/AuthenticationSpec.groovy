package ee.ria.tara

import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Unroll

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo
import static org.junit.Assert.assertEquals

class AuthenticationSpec extends TaraSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("AUTHENTICATION")
    def "request authentication"() {
        expect:
        Response initClientAuthenticationSession = Steps.createAuthenticationSession(flow)
        assertEquals("Correct HTTP status code is returned", 302, initClientAuthenticationSession.statusCode())

        Response initOIDCServiceSession = Steps.createOIDCSession(flow, initClientAuthenticationSession)
        assertEquals("Correct HTTP status code is returned", 302, initOIDCServiceSession.statusCode())

        Response initLoginSession = Steps.createLoginSession(flow, initOIDCServiceSession)
        assertEquals("Correct HTTP status code is returned", 200, initLoginSession.statusCode())

        Response midInit = Requests.initMid(flow)
        assertEquals("Correct HTTP status code is returned", 200, midInit.statusCode())
        Response midPollResult = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, midPollResult.statusCode())
        Response acceptResponse = Requests.followRedirectWithSessionId(flow, REQUEST_TYPE_POST, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 302, acceptResponse.statusCode())

        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        assertEquals("Correct HTTP status code is returned", 302, oidcServiceResponse.statusCode())

        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        assertEquals("Correct HTTP status code is returned", 302, consentResponse.statusCode())
        Response oidcserviceResponse = Steps.followRedirectWithCookies(flow, consentResponse, flow.oidcService.cookies)
        assertEquals("Correct HTTP status code is returned", 302, oidcserviceResponse.statusCode())

        Response webTokenResponse = Steps.followRedirectWithCookies(flow, oidcserviceResponse, flow.oidcClient.cookies)
        assertEquals("Correct HTTP status code is returned", 200, webTokenResponse.statusCode())
        Map<String, String> webToken = webTokenResponse.body().jsonPath().getMap("\$.")
        JWTClaimsSet claims = TokenUtils.verifyTokenAndReturnSignedJwtObject(webToken.get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClient.clientId))
        assertThat(claims.getSubject(), equalTo("EE60001017716"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("ONE"))
    }


}
