package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.hamcrest.Matchers
import spock.lang.Ignore
import spock.lang.Unroll

import static org.hamcrest.Matchers.equalTo
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat
import static org.junit.Assert.assertTrue

class AuthenticationSpec extends TaraSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
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
        assertThat(midPollResult.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 302, acceptResponse.statusCode())

        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        assertEquals("Correct HTTP status code is returned", 302, oidcServiceResponse.statusCode())

        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        assertEquals("Correct HTTP status code is returned", 200, consentResponse.statusCode())
        Response consentConfirmResponse = Steps.consentConfirmation(flow, true)
        assertEquals("Correct HTTP status code is returned", 302, consentConfirmResponse.statusCode())
        Response oidcserviceResponse = Steps.followRedirectWithCookies(flow, consentConfirmResponse, flow.oidcService.cookies)
        assertEquals("Correct HTTP status code is returned", 302, oidcserviceResponse.statusCode())

        Response webTokenResponse = Steps.followRedirectWithCookies(flow, oidcserviceResponse, flow.oidcClient.cookies)
        assertEquals("Correct HTTP status code is returned", 200, webTokenResponse.statusCode())
        Map<String, String> webToken = webTokenResponse.body().jsonPath().getMap("\$.")
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, webToken.get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClient.clientId))
        assertThat(claims.getSubject(), equalTo("EE60001017716"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("ONE"))
    }

    @Unroll
    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("SECURE_COOKIE_HANDLING")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "request authentication with security checks"() {
        expect:
        Response initClientAuthenticationSession = Steps.createAuthenticationSession(flow)
        assertEquals("Correct HTTP status code is returned", 302, initClientAuthenticationSession.statusCode())

        Response initOIDCServiceSession = Steps.createOIDCSession(flow, initClientAuthenticationSession)
        assertEquals("Correct HTTP status code is returned", 302, initOIDCServiceSession.statusCode())

        Response initLoginSession = Steps.createLoginSession(flow, initOIDCServiceSession)
        assertEquals("Correct HTTP status code is returned", 200, initLoginSession.statusCode())
        Steps.verifyResponseHeaders(initLoginSession)
        assertThat(initLoginSession.getDetailedCookie("SESSION").toString(), Matchers.containsString("HttpOnly"))
        assertThat(initLoginSession.getDetailedCookie("SESSION").toString(), Matchers.containsString("SameSite=Strict"))
        Response midInit = Requests.initMid(flow)
        assertEquals("Correct HTTP status code is returned", 200, midInit.statusCode())
        Steps.verifyResponseHeaders(midInit)
        Response midPollResult = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, midPollResult.statusCode())
        assertThat(midPollResult.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        // TARA2-178
        // Steps.verifyResponseHeaders(midPollResult)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 302, acceptResponse.statusCode())
        Steps.verifyResponseHeaders(acceptResponse)
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        assertEquals("Correct HTTP status code is returned", 302, oidcServiceResponse.statusCode())

        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        assertEquals("Correct HTTP status code is returned", 200, consentResponse.statusCode())
        Steps.verifyResponseHeaders(consentResponse)

        Response consentConfirmResponse = Steps.consentConfirmation(flow, true)
        assertEquals("Correct HTTP status code is returned", 302, consentConfirmResponse.statusCode())
        Steps.verifyResponseHeaders(consentConfirmResponse)
        Response oidcserviceResponse = Steps.followRedirectWithCookies(flow, consentConfirmResponse, flow.oidcService.cookies)
        assertEquals("Correct HTTP status code is returned", 302, oidcserviceResponse.statusCode())

        Response webTokenResponse = Steps.followRedirectWithCookies(flow, oidcserviceResponse, flow.oidcClient.cookies)
        assertEquals("Correct HTTP status code is returned", 200, webTokenResponse.statusCode())
        Map<String, String> webToken = webTokenResponse.body().jsonPath().getMap("\$.")
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, webToken.get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClient.clientId))
        assertThat(claims.getSubject(), equalTo("EE60001017716"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("ONE"))
    }

    @Unroll
    @Feature("AUTH_ACCEPT_LOGIN_ENDPOINT")
    def "request accept authentication"() {
        expect:
        Response initClientAuthenticationSession = Steps.initAuthenticationSession(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, pollResponse.statusCode())
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        assertThat(response.getHeader("location"), Matchers.startsWith(flow.oidcService.fullAuthenticationRequestUrl))
        assertEquals("Location field contains correct client_id value", flow.oidcClient.clientId, Utils.getParamValueFromResponseHeader(response, "client_id"))
    }

    @Ignore // TARA2-82 , TARA2-165
    @Unroll
    @Feature("AUTH_ACCEPT_LOGIN_ENDPOINT")
    def "request accept authentication with invalid method get"() {
        expect:
        Response initClientAuthenticationSession = Steps.initAuthenticationSession(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, pollResponse.statusCode())
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        Response response = Requests.getRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), equalTo("Request method 'GET' not supported"))
    }

    @Unroll
    @Feature("AUTH_ACCEPT_LOGIN_ENDPOINT")
    def "request accept authentication with invalid session ID"() {
        expect:
        Response initClientAuthenticationSession = Steps.initAuthenticationSession(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, pollResponse.statusCode())
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        flow.setSessionId("1234567")
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 403, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertEquals("Correct error message is returned", "Forbidden", response.body().jsonPath().get("message"))
        assertTrue(response.body().jsonPath().get("incident_nr").toString().size() > 15)
    }

    @Unroll
    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "request reject authentication"() {
        expect:
        Response initClientAuthenticationSession = Steps.initAuthenticationSession(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, pollResponse.statusCode())
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "error_code", REJECT_ERROR_CODE)
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(cookieMap, "SESSION", flow.sessionId)
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, cookieMap, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        assertThat(response.getHeader("location"), Matchers.startsWith(flow.oidcService.fullAuthenticationRequestUrl))
        assertEquals("Location field contains correct client_id value", flow.oidcClient.clientId, Utils.getParamValueFromResponseHeader(response, "client_id"))
        Response oidcserviceResponse = Steps.followRedirectWithCookies(flow, response, flow.oidcService.cookies)
        assertEquals("Correct HTTP status code is returned", 302, oidcserviceResponse.statusCode())
        assertThat(oidcserviceResponse.getHeader("location"), Matchers.containsString("user_cancel"))
    }

    @Unroll
    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Verify reject authentication response headers"() {
        expect:
        Response initClientAuthenticationSession = Steps.initAuthenticationSession(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, pollResponse.statusCode())
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "error_code", REJECT_ERROR_CODE)
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(cookieMap, "SESSION", flow.sessionId)
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, cookieMap, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
       Steps.verifyResponseHeaders(response)
    }

    @Unroll
    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "request reject authentication with invalid error_code value"() {
        expect:
        Response initClientAuthenticationSession = Steps.initAuthenticationSession(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, pollResponse.statusCode())
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "error_code", "ERROR12345")
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(cookieMap, "SESSION", flow.sessionId)
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, cookieMap, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertEquals("Correct error message is returned", "authReject.errorCode: the only supported value is: 'user_cancel'", response.body().jsonPath().get("message"))
        assertTrue(response.body().jsonPath().get("incident_nr").toString().size() > 15)
    }

    @Unroll
    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "request reject authentication with invalid session ID"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "error_code", REJECT_ERROR_CODE)
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(cookieMap, "SESSION", "S34567")
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, cookieMap, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }

    @Unroll
    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "request reject authentication with missing session ID"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "error_code", REJECT_ERROR_CODE)
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, Collections.emptyMap(), paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }
    
    @Ignore // TARA2-104
    @Unroll
    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "request reject authentication with invalid method post"() {
        expect:
        Response initClientAuthenticationSession = Steps.initAuthenticationSession(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, pollResponse.statusCode())
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "error_code", REJECT_ERROR_CODE)
        def map2 = Utils.setParameter(paramsMap, "_csrf", flow.csrf)
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(cookieMap, "SESSION", flow.sessionId)
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, cookieMap, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), equalTo("Request method 'POST' not supported"))
    }

    @Unroll
    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "request reject authentication with multiple error_code values"() {
        expect:
        Response initClientAuthenticationSession = Steps.initAuthenticationSession(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, pollResponse.statusCode())
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "error_code", "ERROR12345")
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(cookieMap, "SESSION", flow.sessionId)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        def map4 = Utils.setParameter(additionalParamsMap, "error_code", REJECT_ERROR_CODE)
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, cookieMap, paramsMap, additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertEquals("Correct error message is returned", "Multiple request parameters with the same name not allowed", response.body().jsonPath().get("message"))
        assertTrue(response.body().jsonPath().get("incident_nr").toString().size() > 15)
    }
}
