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
        Steps.startAuthenticationInTara(flow)
        Steps.authenticateWithMid(flow,"60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClient.clientId))
        assertThat(claims.getSubject(), equalTo("EE60001017716"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("ONE"))
    }

    @Ignore // Etapp4
    @Unroll
    @Feature("AUTHENTICATION")
    def "request authentication with Smart-ID"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Steps.authenticateWithSid(flow,"10101010005")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClient.clientId))
        assertThat(claims.getSubject(), equalTo("EE10101010005"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("DEMO"))
    }

    @Ignore //Etapp4
    @Unroll
    @Feature("AUTHENTICATION")
    def "request authentication with Eidas"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        String country = "CA"
        Response initEidasAuthenticationSession = Steps.initEidasAuthSession(flow, flow.sessionId, country, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initEidasAuthenticationSession.statusCode())
        assertEquals("Correct Content-Type is returned", "text/html;charset=UTF-8", initEidasAuthenticationSession.getContentType())
        String buttonLabel = initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@type == 'submit'}.@value")
        assertEquals("Continue button exists", "Continue", buttonLabel)

        flow.setNextEndpoint(initEidasAuthenticationSession.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response colleagueResponse = Steps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA)
        Response authorizationResponse = Steps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        Response redirectionResponse = Steps.eidasRedirectAuthorizationResponse(flow, authorizationResponse)
        Response acceptResponse = Steps.eidasAcceptAuthorizationResult(flow, redirectionResponse)
        assertEquals("Correct HTTP status code is returned", 302, acceptResponse.statusCode())
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClient.clientId))
        assertThat(claims.getSubject(), equalTo("CACA/EE/12345"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("javier"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("family_name"), equalTo("Garcia"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("date_of_birth"), equalTo("1965-01-01"))
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
        Response initLoginSession = Steps.startAuthenticationInTara(flow)
        assertEquals("Correct HTTP status code is returned", 200, initLoginSession.statusCode())
        Steps.verifyResponseHeaders(initLoginSession)
        assertThat(initLoginSession.getDetailedCookie("SESSION").toString(), Matchers.containsString("HttpOnly"))
        assertThat(initLoginSession.getDetailedCookie("SESSION").toString(), Matchers.containsString("SameSite=Strict"))
        Response midInit = Requests.startMidAuthentication(flow, "60001017716", "69100366")
        assertEquals("Correct HTTP status code is returned", 200, midInit.statusCode())
        Steps.verifyResponseHeaders(midInit)
        Response midPollResult = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, midPollResult.statusCode())
        assertThat(midPollResult.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        Steps.verifyResponseHeaders(midPollResult)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 302, acceptResponse.statusCode())
        Steps.verifyResponseHeaders(acceptResponse)
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        assertEquals("Correct HTTP status code is returned", 302, oidcServiceResponse.statusCode())

        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        assertEquals("Correct HTTP status code is returned", 200, consentResponse.statusCode())
        Steps.verifyResponseHeaders(consentResponse)

        Response consentConfirmResponse = Steps.submitConsent(flow, true)
        assertEquals("Correct HTTP status code is returned", 302, consentConfirmResponse.statusCode())
        Steps.verifyResponseHeaders(consentConfirmResponse)

        Response oidcserviceResponse = Steps.followRedirectWithCookies(flow, consentConfirmResponse, flow.oidcService.cookies)
        assertEquals("Correct HTTP status code is returned", 302, oidcserviceResponse.statusCode())
        String authorizationCode = Utils.getParamValueFromResponseHeader(oidcserviceResponse, "code")
        Response tokenResponse = Requests.getWebToken(flow, authorizationCode)

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClient.clientId))
        assertThat(claims.getSubject(), equalTo("EE60001017716"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("ONE"))
    }

    @Unroll
    @Feature("AUTH_ACCEPT_LOGIN_ENDPOINT")
    def "request accept authentication"() {
        expect:
        Steps.startAuthenticationInTara(flow)
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
        Steps.startAuthenticationInTara(flow)
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
        Steps.startAuthenticationInTara(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, pollResponse.statusCode())
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        flow.setSessionId("1234567")
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 403, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertThat(response.body().jsonPath().get("error").toString(), equalTo("Forbidden"))
        String message = "Keelatud päring. Päring esitati topelt, sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."
        assertThat(response.body().jsonPath().get("message").toString(), equalTo(message))
        assertTrue(response.body().jsonPath().get("incident_nr").toString().size() > 15)
    }

    @Unroll
    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "request reject authentication"() {
        expect:
        Steps.startAuthenticationInTara(flow)
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
        Steps.startAuthenticationInTara(flow)
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
        Steps.startAuthenticationInTara(flow)
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
    
    @Ignore // TARA2-104 , TARA2-165
    @Unroll
    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "request reject authentication with invalid method post"() {
        expect:
        Steps.startAuthenticationInTara(flow)
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
        Steps.startAuthenticationInTara(flow)
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
