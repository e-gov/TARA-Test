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
import static org.junit.jupiter.api.Assertions.*
import static org.hamcrest.MatcherAssert.assertThat

class AuthenticationSpec extends TaraSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Unroll
    @Feature("AUTHENTICATION")
    def "request authentication with mobile-ID"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response midAuthResponse = Steps.authenticateWithMid(flow,"60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientPublic.clientId))
        assertThat(claims.getSubject(), equalTo("EE60001017716"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("ONE"))
    }

    @Unroll
    @Feature("AUTHENTICATION")
    def "request authentication with mobile-ID. TEST of EID-SK 2016 chain certificate"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response midAuthResponse = Steps.authenticateWithMid(flow,"60001017869", "68000769")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientPublic.clientId))
        assertThat(claims.getSubject(), equalTo("EE60001017869"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("EID2016"))
    }

    @Unroll
    @Feature("AUTHENTICATION")
    def "request authentication with Smart-ID"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Response sidAuthResponse = Steps.authenticateWithSid(flow,"30303039914")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, sidAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientPublic.clientId))
        assertThat(claims.getSubject(), equalTo("EE30303039914"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("QUALIFIED OK1"))
    }

    @Unroll
    @Feature("AUTHENTICATION")
    def "request authentication with eIDAS"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        String country = "CA"
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.sessionId, country, Collections.emptyMap())
        assertEquals(200, initEidasAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", initEidasAuthenticationSession.getContentType(), "Correct Content-Type is returned")
        String buttonLabel = initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@type == 'submit'}.@value")
        assertEquals("Continue", buttonLabel, "Continue button exists")

        flow.setNextEndpoint(initEidasAuthenticationSession.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA)
        Response authorizationResponse = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        Response redirectionResponse = EidasSteps.eidasRedirectAuthorizationResponse(flow, authorizationResponse)
        Response acceptResponse = EidasSteps.eidasAcceptAuthorizationResult(flow, redirectionResponse)
        assertEquals(302, acceptResponse.statusCode(), "Correct HTTP status code is returned")
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        Response redirectResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, redirectResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientPublic.clientId))
        assertThat(claims.getSubject(), equalTo("CA12345"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("javier"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("family_name"), equalTo("Garcia"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("date_of_birth"), equalTo("1965-01-01"))
    }

    @Unroll
    @Feature("AUTHENTICATION")
    def "request authentication with eIDAS with privet sector client"() {
        expect:
        Steps.startAuthenticationInTaraWithClient(flow, "openid eidas", flow.oidcClientPrivate.clientId, flow.oidcClientPrivate.fullResponseUrl)
        String country = "CA"
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.sessionId, country, Collections.emptyMap())
        assertEquals(200, initEidasAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", initEidasAuthenticationSession.getContentType(), "Correct Content-Type is returned")
        String buttonLabel = initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@type == 'submit'}.@value")
        assertEquals("Continue", buttonLabel, "Continue button exists")

        flow.setNextEndpoint(initEidasAuthenticationSession.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA)
        Response authorizationResponse = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        Response redirectionResponse = EidasSteps.eidasRedirectAuthorizationResponse(flow, authorizationResponse)
        Response acceptResponse = EidasSteps.eidasAcceptAuthorizationResult(flow, redirectionResponse)
        assertEquals(302, acceptResponse.statusCode(), "Correct HTTP status code is returned")
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        Response redirectResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, redirectResponse)
        Response tokenResponse = Steps.getIdentityTokenResponseWithClient(flow, authenticationFinishedResponse, flow.oidcClientPrivate.fullResponseUrl, flow.oidcClientPrivate.clientId, flow.oidcClientPrivate.clientSecret)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientPrivate.clientId))
        assertThat(claims.getSubject(), equalTo("CA12345"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("javier"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("family_name"), equalTo("Garcia"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("date_of_birth"), equalTo("1965-01-01"))
    }


    @Unroll
    @Feature("AUTHENTICATION")
    def "request authentication with mobile-ID with Specific Proxy Service as OIDC client"() {
        expect:
        Steps.startAuthenticationInTaraWithSpecificProxyService(flow)
        Response midAuthResponse = Steps.authenticateWithMid(flow,"60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponseWithClient(flow, authenticationFinishedResponse, flow.specificProxyService.fullResponseUrl, flow.specificProxyService.clientId, flow.specificProxyService.clientSecret)

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.specificProxyService.clientId))
        assertThat(claims.getSubject(), equalTo("EE60001017716"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("ONE"))
    }

    @Unroll
    @Feature("AUTHENTICATION")
    def "request authentication with Eidas. Low level of assurance."() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        String country = "CA"
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.sessionId, country, Collections.emptyMap())
        assertEquals(200, initEidasAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", initEidasAuthenticationSession.getContentType(), "Correct Content-Type is returned")
        String buttonLabel = initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@type == 'submit'}.@value")
        assertEquals("Continue", buttonLabel, "Continue button exists")

        flow.setNextEndpoint(initEidasAuthenticationSession.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA_LOW)
        Response authorizationResponse = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        String endpointUrl = authorizationResponse.body().htmlPath().get("**.find {it.@method == 'post'}.@action")
        String samlResponse = authorizationResponse.body().htmlPath().get("**.find {it.@name == 'SAMLResponse'}.@value")
        String relayState = authorizationResponse.body().htmlPath().get("**.find {it.@name == 'RelayState'}.@value")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "SAMLResponse" , samlResponse)
        Utils.setParameter(paramsMap, "RelayState", relayState)
        Response redirectionResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap, Collections.emptyMap())
        assertThat(redirectionResponse.body().jsonPath().get("status"), equalTo(400))
        assertThat(redirectionResponse.body().jsonPath().get("message").toString(), equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
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
        assertEquals(200, initLoginSession.statusCode(), "Correct HTTP status code is returned")
        Steps.verifyResponseHeaders(initLoginSession)
        assertThat(initLoginSession.getDetailedCookie("SESSION").toString(), Matchers.containsString("HttpOnly"))
        assertThat(initLoginSession.getDetailedCookie("SESSION").toString(), Matchers.containsString("SameSite=Strict"))
        Response midInit = Requests.startMidAuthentication(flow, "60001017716", "69100366")
        assertEquals(200, midInit.statusCode(), "Correct HTTP status code is returned")
        Steps.verifyResponseHeaders(midInit)
        Response midPollResult = Steps.pollMidResponse(flow)
        assertEquals(200, midPollResult.statusCode(), "Correct HTTP status code is returned")
        assertThat(midPollResult.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        Steps.verifyResponseHeaders(midPollResult)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals(302, acceptResponse.statusCode(), "Correct HTTP status code is returned")
        Steps.verifyResponseHeaders(acceptResponse)
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        assertEquals(302, oidcServiceResponse.statusCode(), "Correct HTTP status code is returned")

        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        Steps.verifyResponseHeaders(consentResponse)

        if (consentResponse.getStatusCode() == 200) {
            consentResponse = Steps.submitConsent(flow, true)
            assertEquals(302, consentResponse.statusCode(), "Correct HTTP status code is returned")
            Steps.verifyResponseHeaders(consentResponse)
        }

        Response oidcserviceResponse = Steps.followRedirectWithCookies(flow, consentResponse, flow.oidcService.cookies)
        assertEquals(303, oidcserviceResponse.statusCode(), "Correct HTTP status code is returned")
        String authorizationCode = Utils.getParamValueFromResponseHeader(oidcserviceResponse, "code")
        Response tokenResponse = Requests.getWebToken(flow, authorizationCode)

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientPublic.clientId))
        assertThat(claims.getSubject(), equalTo("EE60001017716"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("ONE"))
    }

    @Unroll
    @Feature("AUTH_ACCEPT_LOGIN_ENDPOINT")
    def "request accept authentication"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", Collections.emptyMap())
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals(200, pollResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals(302, response.statusCode(), "Correct HTTP status code is returned")
        assertThat(response.getHeader("location"), Matchers.startsWith(flow.openIdServiceConfiguration.getString("authorization_endpoint")))
        assertEquals(flow.oidcClientPublic.clientId, Utils.getParamValueFromResponseHeader(response, "client_id"), "Location field contains correct client_id value")
    }

    @Ignore // TARA2-82 , TARA2-165
    @Unroll
    @Feature("AUTH_ACCEPT_LOGIN_ENDPOINT")
    def "request accept authentication with invalid method get"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", Collections.emptyMap())
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals(200, pollResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        Response response = Requests.getRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertThat(response.body().jsonPath().get("message").toString(), equalTo("Request method 'GET' not supported"))
    }

    @Unroll
    @Feature("AUTH_ACCEPT_LOGIN_ENDPOINT")
    def "request accept authentication with invalid session ID"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", Collections.emptyMap())
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals(200, pollResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        flow.setSessionId("1234567")
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals(403, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertThat(response.body().jsonPath().get("error").toString(), equalTo("Forbidden"))
        String message = "Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."
        assertThat(response.body().jsonPath().get("message").toString(), equalTo(message))
        assertTrue(response.body().jsonPath().get("incident_nr").toString().size() > 15)
    }

    @Unroll
    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "request reject authentication"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", Collections.emptyMap())
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals(200, pollResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "error_code", REJECT_ERROR_CODE)
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(cookieMap, "SESSION", flow.sessionId)
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, cookieMap, paramsMap, Collections.emptyMap())
        assertEquals(302, response.statusCode(), "Correct HTTP status code is returned")
        assertThat(response.getHeader("location"), Matchers.startsWith(flow.openIdServiceConfiguration.getString("authorization_endpoint")))
        assertEquals(flow.oidcClientPublic.clientId, Utils.getParamValueFromResponseHeader(response, "client_id"), "Location field contains correct client_id value")
        Response oidcserviceResponse = Steps.followRedirectWithCookies(flow, response, flow.oidcService.cookies)
        assertEquals(303, oidcserviceResponse.statusCode(), "Correct HTTP status code is returned")
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
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals(200, pollResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "error_code", REJECT_ERROR_CODE)
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(cookieMap, "SESSION", flow.sessionId)
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, cookieMap, paramsMap, Collections.emptyMap())
        assertEquals(302, response.statusCode(), "Correct HTTP status code is returned")
       Steps.verifyResponseHeaders(response)
    }

    @Unroll
    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "request reject authentication with invalid error_code value"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", Collections.emptyMap())
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals(200, pollResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "error_code", "ERROR12345")
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(cookieMap, "SESSION", flow.sessionId)
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, cookieMap, paramsMap, Collections.emptyMap())
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertEquals("authReject.errorCode: the only supported value is: 'user_cancel'", response.body().jsonPath().get("message"), "Correct error message is returned")
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
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertEquals("Teie seanssi ei leitud! Seanss aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"), "Correct error message is returned")
    }

    @Unroll
    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "request reject authentication with missing session ID"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "error_code", REJECT_ERROR_CODE)
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, Collections.emptyMap(), paramsMap, Collections.emptyMap())
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertEquals("Teie seanssi ei leitud! Seanss aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"), "Correct error message is returned")
    }
    
    @Ignore // TARA2-104 , TARA2-165
    @Unroll
    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "request reject authentication with invalid method post"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", Collections.emptyMap())
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals(200, pollResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "error_code", REJECT_ERROR_CODE)
        def map2 = Utils.setParameter(paramsMap, "_csrf", flow.csrf)
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(cookieMap, "SESSION", flow.sessionId)
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, cookieMap, paramsMap, Collections.emptyMap())
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), equalTo("Request method 'POST' not supported"))
    }

    @Unroll
    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "request reject authentication with multiple error_code values"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", Collections.emptyMap())
        assertEquals(200, initMidAuthenticationSession.statusCode(),"Correct HTTP status code is returned")
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals(200, pollResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "error_code", "ERROR12345")
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(cookieMap, "SESSION", flow.sessionId)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        def map4 = Utils.setParameter(additionalParamsMap, "error_code", REJECT_ERROR_CODE)
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, cookieMap, paramsMap, additionalParamsMap)
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertEquals("Multiple request parameters with the same name not allowed", response.body().jsonPath().get("message"), "Correct error message is returned")
        assertTrue(response.body().jsonPath().get("incident_nr").toString().size() > 15)
    }
}
