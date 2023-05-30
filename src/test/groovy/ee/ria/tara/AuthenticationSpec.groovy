package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.hasLength
import static org.hamcrest.Matchers.startsWith
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.not
import static org.hamcrest.Matchers.containsString


class AuthenticationSpec extends TaraSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Feature("AUTHENTICATION")
    def "request authentication with mobile-ID: #certificate certificate chain"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Response midAuthResponse = Steps.authenticateWithMid(flow, idCode, phoneNumber)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience[0], is(flow.oidcClientPublic.clientId))
        assertThat("Correct subject", claims.subject, is(subject))

        where:
        certificate              | idCode        | phoneNumber || subject
        "TEST of ESTEID-SK 2015" | "60001017716" | "69100366"  || "EE" + idCode
        "TEST of EID-SK 2016"    | "60001017869" | "68000769"  || "EE" + idCode
    }

    @Feature("AUTHENTICATION")
    def "request authentication with Smart-ID"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Response sidAuthResponse = Steps.authenticateWithSid(flow, "30303039914")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, sidAuthResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience[0], is(flow.oidcClientPublic.clientId))
        assertThat("Correct subject", claims.subject, is("EE30303039914"))
    }

    @Feature("AUTHENTICATION")
    def "request authentication with eIDAS. LoA: #eidasLoa "() {
        given:
        Steps.startAuthenticationInTaraWithAcr(flow, acr)
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.sessionId, COUNTRY_CA, [:])

        flow.setNextEndpoint(initEidasAuthenticationSession.htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, eidasLoa)
        Response authorizationResponse = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        Response redirectionResponse = EidasSteps.eidasRedirectAuthorizationResponse(flow, authorizationResponse)
        Response acceptResponse = EidasSteps.eidasAcceptAuthorizationResult(flow, redirectionResponse)
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        Response redirectResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, redirectResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience[0], is(flow.oidcClientPublic.clientId))
        assertThat("Correct acr", claims.claims["acr"], is(acr))
        assertThat("Correct subject", claims.subject, is("CA12345"))

        where:
        eidasLoa              || acr
        EIDASLOA_HIGH         || "high"
        EIDASLOA_NOT_NOTIFIED || "low"
    }

    @Feature("AUTHENTICATION")
    def "request authentication with eIDAS with privet sector client"() {
        given:
        Steps.startAuthenticationInTaraWithClient(flow, "openid eidas", flow.oidcClientPrivate.clientId, flow.oidcClientPrivate.fullResponseUrl)
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.sessionId, COUNTRY_CA, [:])

        flow.setNextEndpoint(initEidasAuthenticationSession.htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA_HIGH)
        Response authorizationResponse = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        Response redirectionResponse = EidasSteps.eidasRedirectAuthorizationResponse(flow, authorizationResponse)
        Response acceptResponse = EidasSteps.eidasAcceptAuthorizationResult(flow, redirectionResponse)
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        Response redirectResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, redirectResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponseWithClient(flow, authenticationFinishedResponse, flow.oidcClientPrivate.fullResponseUrl, flow.oidcClientPrivate.clientId, flow.oidcClientPrivate.clientSecret)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat(claims.audience[0], is(flow.oidcClientPrivate.clientId))
        assertThat(claims.subject, is("CA12345"))
        assertThat(claims.getJSONObjectClaim("profile_attributes")["given_name"], is("javier"))
        assertThat(claims.getJSONObjectClaim("profile_attributes")["family_name"], is("Garcia"))
        assertThat(claims.getJSONObjectClaim("profile_attributes")["date_of_birth"], is("1965-01-01"))
    }

    @Feature("AUTHENTICATION")
    def "request authentication with mobile-ID with Specific Proxy Service as OIDC client"() {
        given:
        Steps.startAuthenticationInTaraWithSpecificProxyService(flow)
        Response midAuthResponse = Steps.authenticateWithMid(flow, "60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponseWithClient(flow, authenticationFinishedResponse, flow.specificProxyService.fullResponseUrl, flow.specificProxyService.clientId, flow.specificProxyService.clientSecret)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get('id_token')).JWTClaimsSet

        then:
        assertThat(claims.audience[0], is(flow.specificProxyService.clientId))
        assertThat(claims.subject, is("EE60001017716"))
        assertThat(claims.getJSONObjectClaim("profile_attributes")["given_name"], is("ONE"))
    }

    @Feature("AUTHENTICATION")
    def "request authentication with Eidas. Low level of assurance."() {
        given:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.sessionId, COUNTRY_CA, [:])

        flow.setNextEndpoint(initEidasAuthenticationSession.htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA_LOW)
        Response authorizationResponse = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        String endpointUrl = authorizationResponse.htmlPath().get("**.find {it.@method == 'post'}.@action")
        String samlResponse = authorizationResponse.htmlPath().get("**.find {it.@name == 'SAMLResponse'}.@value")
        String relayState = authorizationResponse.htmlPath().get("**.find {it.@name == 'RelayState'}.@value")
        Map paramsMap = [
                "SAMLResponse": samlResponse,
                "RelayState"  : relayState]

        when:
        Response redirectionResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap, [:])

        then:
        assertThat("Correct HTTP status code", redirectionResponse.statusCode, is(400))
        assertThat(redirectionResponse.jsonPath().get("message").toString(), is("Teie poolt valitud välisriigi autentimisvahend on teenuse poolt nõutust madalama autentimistasemega. Palun valige mõni muu autentimisvahend."))
    }

    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("SECURE_COOKIE_HANDLING")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "request authentication with security checks"() {
        given:
        Response initLoginSession = Steps.startAuthenticationInTara(flow)
        Steps.verifyResponseHeaders(initLoginSession)
        assertThat(initLoginSession.getDetailedCookie("SESSION").toString(), containsString("HttpOnly"))
        assertThat(initLoginSession.getDetailedCookie("SESSION").toString(), containsString("SameSite=Strict"))
        Response midInit = Requests.startMidAuthentication(flow, "60001017716", "69100366")
        Steps.verifyResponseHeaders(midInit)
        Response midPollResult = Steps.pollMidResponse(flow)
        assertThat(midPollResult.jsonPath().get("status").toString(), not(equalTo("PENDING")))
        Steps.verifyResponseHeaders(midPollResult)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        Steps.verifyResponseHeaders(acceptResponse)
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)

        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        Steps.verifyResponseHeaders(consentResponse)

        if (consentResponse.statusCode == 200) {
            consentResponse = Steps.submitConsent(flow, true)
            Steps.verifyResponseHeaders(consentResponse)
        }

        Response oidcserviceResponse = Steps.followRedirectWithCookies(flow, consentResponse, flow.oidcService.cookies)
        String authorizationCode = Utils.getParamValueFromResponseHeader(oidcserviceResponse, "code")

        when:
        Response tokenResponse = Requests.getWebToken(flow, authorizationCode)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat(claims.audience[0], is(flow.oidcClientPublic.clientId))
        assertThat(claims.subject, is("EE60001017716"))
        assertThat(claims.getJSONObjectClaim("profile_attributes")["given_name"], is("ONE"))
    }

    @Feature("AUTH_ACCEPT_LOGIN_ENDPOINT")
    def "request accept authentication"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366")
        Steps.pollMidResponse(flow)

        when:
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(302))
        assertThat("Correct URL", response.header("location"), startsWith(flow.openIdServiceConfiguration.getString("authorization_endpoint")))
        assertThat("Location field contains correct client_id value", Utils.getParamValueFromResponseHeader(response, "client_id"), is(flow.oidcClientPublic.clientId))
    }

    @Feature("AUTH_ACCEPT_LOGIN_ENDPOINT")
    def "request accept authentication with invalid method get"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366")
        Steps.pollMidResponse(flow)

        when:
        Response response = Requests.getRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat('Correct Content-Type', response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString('message'), is(MESSAGE_INTERNAL_ERROR))
    }

    @Feature("AUTH_ACCEPT_LOGIN_ENDPOINT")
    def "request accept authentication with invalid session ID"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366")
        Steps.pollMidResponse(flow)
        flow.setSessionId("1234567")

        when:
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(403))
        assertThat('Correct Content-Type', response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_FORBIDDEN))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_FORBIDDEN_REQUEST))
        assertThat("Incident number is present", response.jsonPath().getString("incident_nr"), hasLength(32))
    }

    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "request reject authentication"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366")
        Steps.pollMidResponse(flow)
        Map paramsMap = ["error_code": REJECT_ERROR_CODE]
        Map cookieMap = ["SESSION": flow.sessionId]
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, cookieMap, paramsMap, [:])

        when:
        Response oidcServiceResponse = Steps.followRedirectWithCookies(flow, response, flow.oidcService.cookies)

        then:
        assertThat("Correct HTTP status code", oidcServiceResponse.statusCode, is(303))
        assertThat("Correct error in URL", oidcServiceResponse.header("location"), containsString(REJECT_ERROR_CODE))
    }

    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Verify reject authentication response headers"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366")
        Steps.pollMidResponse(flow)
        Map paramsMap = ["error_code": REJECT_ERROR_CODE]
        Map cookieMap = ["SESSION": flow.sessionId]

        when:
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, cookieMap, paramsMap, [:])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(302))
        Steps.verifyResponseHeaders(response)
    }

    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "request reject authentication with invalid error_code value"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366")
        Steps.pollMidResponse(flow)
        Map paramsMap = ["error_code": "ERROR12345"]
        Map cookieMap = ["SESSION": flow.sessionId]

        when:
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, cookieMap, paramsMap, [:])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString("message"), is("authReject.errorCode: the only supported value is: \'user_cancel\'"))
        assertThat("Incident number is present", response.jsonPath().getString("incident_nr"), hasLength(32))
    }

    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "request reject authentication with invalid session ID"() {
        given:
        Map paramsMap = ["error_code": REJECT_ERROR_CODE]
        Map cookieMap = ["SESSION": "S34567"]

        when:
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, cookieMap, paramsMap, [:])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString("message"), is(MESSAGE_SESSION_NOT_FOUND))
    }

    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "request reject authentication with missing session ID"() {
        given:
        Map paramsMap = ["error_code": REJECT_ERROR_CODE]

        when:
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, [:], paramsMap, [:])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString("message"), is(MESSAGE_SESSION_NOT_FOUND))
    }

    //TODO: AUT-630
    def "request reject authentication with invalid method post"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366")
        Steps.pollMidResponse(flow)
        Map paramsMap = [
                "error_code": REJECT_ERROR_CODE,
                "_csrf"     : flow.csrf]
        Map cookieMap = ["SESSION": flow.sessionId]

        when:
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, cookieMap, paramsMap, [:])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString('message'), is(MESSAGE_INTERNAL_ERROR))
    }

    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "request reject authentication with multiple error_code values"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366")
        Steps.pollMidResponse(flow)
        Map paramsMap = ["error_code": "ERROR12345"]
        Map cookieMap = ["SESSION": flow.sessionId]
        Map additionalParamsMap = ["error_code": REJECT_ERROR_CODE]

        when:
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, cookieMap, paramsMap, additionalParamsMap)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString('message'), is(MESSAGE_DUPLICATE_PARAMETERS))
        assertThat("Incident number is present", response.jsonPath().getString("incident_nr"), hasLength(32))
    }
}
