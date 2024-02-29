package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.qameta.allure.Step
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static io.restassured.RestAssured.given
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
    def "Request authentication with mobile-ID: #certificate certificate chain"() {
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
    def "Request authentication with Smart-ID"() {
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
    def "Authenticate with Smart-ID with custom relying party name and UUID"() {
        given:
        Steps.startAuthenticationInTaraWithClient(flow, "SysTest-Relying-Party-client", "secret", "https://rp-client.test/oauth/response")
        Response sidAuthResponse = Steps.authenticateWithSid(flow, "30303039914")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, sidAuthResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponseWithClient(flow, authenticationFinishedResponse,"SysTest-Relying-Party-client", "secret", "https://rp-client.test/oauth/response")
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience[0], is("SysTest-Relying-Party-client"))
        assertThat("Correct subject", claims.subject, is("EE30303039914"))
    }

    @Feature("AUTHENTICATION")
    def "Request authentication with eIDAS. LoA: #eidasLoa "() {
        given:
        Steps.startAuthenticationInTaraWithAcr(flow, acr)
        EidasSteps.initEidasAuthSession(flow, COUNTRY_CA)
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, eidasLoa)
        Response authorizationResponse = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        Response redirectionResponse = EidasSteps.eidasRedirectAuthorizationResponse(flow, authorizationResponse)
        Response acceptResponse = EidasSteps.eidasAcceptAuthorizationResult(flow, redirectionResponse)
        Response oidcServiceResponse = Steps.loginVerifier(flow, acceptResponse)
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
    def "Request authentication with eIDAS with privet sector client"() {
        given:
        Steps.startAuthenticationInTaraWithClient(flow, flow.oidcClientPrivate.clientId, flow.oidcClientPrivate.clientSecret, flow.oidcClientPrivate.fullResponseUrl)
        EidasSteps.initEidasAuthSession(flow, COUNTRY_CA)
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA_HIGH)
        Response authorizationResponse = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        Response redirectionResponse = EidasSteps.eidasRedirectAuthorizationResponse(flow, authorizationResponse)
        Response acceptResponse = EidasSteps.eidasAcceptAuthorizationResult(flow, redirectionResponse)
        Response oidcServiceResponse = Steps.loginVerifier(flow, acceptResponse)
        Response redirectResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, redirectResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponseWithClient(flow, authenticationFinishedResponse, flow.oidcClientPrivate.clientId, flow.oidcClientPrivate.clientSecret, flow.oidcClientPrivate.fullResponseUrl)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat(claims.audience[0], is(flow.oidcClientPrivate.clientId))
        assertThat(claims.subject, is("CA12345"))
        assertThat(claims.getJSONObjectClaim("profile_attributes")["given_name"], is("javier"))
        assertThat(claims.getJSONObjectClaim("profile_attributes")["family_name"], is("Garcia"))
        assertThat(claims.getJSONObjectClaim("profile_attributes")["date_of_birth"], is("1965-01-01"))
    }

    @Feature("AUTHENTICATION")
    def "Request authentication with mobile-ID with Specific Proxy Service as OIDC client"() {
        given:
        Steps.startAuthenticationInTaraWithSpecificProxyService(flow)
        Response midAuthResponse = Steps.authenticateWithMid(flow, "60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponseWithClient(flow, authenticationFinishedResponse, flow.specificProxyService.clientId, flow.specificProxyService.clientSecret, flow.specificProxyService.fullResponseUrl)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get('id_token')).JWTClaimsSet

        then:
        assertThat(claims.audience[0], is(flow.specificProxyService.clientId))
        assertThat(claims.subject, is("EE60001017716"))
        assertThat(claims.getJSONObjectClaim("profile_attributes")["given_name"], is("ONE"))
    }

    @Feature("AUTHENTICATION")
    def "Request authentication with Eidas. Low level of assurance."() {
        given:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        EidasSteps.initEidasAuthSession(flow, COUNTRY_CA)
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA_LOW)
        EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)

        when:
        Response redirectionResponse = Requests.postRequestWithParams(flow, flow.nextEndpoint, [SAMLResponse: flow.responseMessage, RelayState: flow.relayState])

        then:
        assertThat("Correct HTTP status code", redirectionResponse.statusCode, is(400))
        assertThat("Correct message", redirectionResponse.jsonPath().getString("message"), is("Teie poolt valitud välisriigi autentimisvahend on teenuse poolt nõutust madalama autentimistasemega. Palun valige mõni muu autentimisvahend."))
    }

    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("SECURE_COOKIE_HANDLING")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Request authentication with security checks"() {
        given:
        Response initLoginSession = Steps.startAuthenticationInTara(flow)
        Steps.verifyResponseHeaders(initLoginSession)
        assertThat(initLoginSession.getDetailedCookie("__Host-SESSION").toString(), containsString("HttpOnly"))
        assertThat(initLoginSession.getDetailedCookie("__Host-SESSION").toString(), containsString("SameSite=Strict"))
        Response midInit = Requests.startMidAuthentication(flow, "60001017716", "69100366")
        Steps.verifyResponseHeaders(midInit)
        Response midPollResult = Steps.pollMidResponse(flow)
        assertThat(midPollResult.jsonPath().getString("status"), not(equalTo("PENDING")))
        Steps.verifyResponseHeaders(midPollResult)
        Response acceptResponse = Requests.postRequest(flow, flow.loginService.fullAuthAcceptUrl)
        Steps.verifyResponseHeaders(acceptResponse)
        Response oidcServiceResponse = Steps.loginVerifier(flow, acceptResponse)

        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        Steps.verifyResponseHeaders(consentResponse)

        if (consentResponse.statusCode == 200) {
            consentResponse = Steps.submitConsent(flow, true)
            Steps.verifyResponseHeaders(consentResponse)
        }

        Response oidcserviceResponse = Steps.followRedirectWithCookies(flow, consentResponse, flow.oidcService.cookies)
        String authorizationCode = Utils.getParamValueFromResponseHeader(oidcserviceResponse, "code")

        when:
        Response tokenResponse = Requests.webTokenBasicRequest(flow, authorizationCode)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat(claims.audience[0], is(flow.oidcClientPublic.clientId))
        assertThat(claims.subject, is("EE60001017716"))
        assertThat(claims.getJSONObjectClaim("profile_attributes")["given_name"], is("ONE"))
    }

    @Feature("AUTH_ACCEPT_LOGIN_ENDPOINT")
    def "Request accept authentication"() {
        given:
        authenticateToPolling(flow)

        when:
        Response response = Requests.postRequest(flow, flow.loginService.fullAuthAcceptUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(302))
        assertThat("Correct URL", response.header("location"), startsWith(flow.openIdServiceConfiguration.getString("authorization_endpoint")))
        assertThat("Location field contains correct client_id value", Utils.getParamValueFromResponseHeader(response, "client_id"), is(flow.oidcClientPublic.clientId))
    }

    @Feature("AUTH_ACCEPT_LOGIN_ENDPOINT")
    def "Request accept authentication with invalid method: #requestType"() {
        given:
        authenticateToPolling(flow)

        when: "request accept authentication with invalid method"
        Response response = given()
                .relaxedHTTPSValidation()
                .cookies("__Host-SESSION": flow.sessionId)
                .params([_csrf: flow.csrf])
                .request(requestType, flow.loginService.fullAuthAcceptUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat('Correct Content-Type', response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString('message'), is(MESSAGE_INTERNAL_ERROR))

        where:
        requestType | _
        "GET"       | _
        "PUT"       | _
        "PATCH"     | _
        "DELETE"    | _
    }

    @Feature("AUTH_ACCEPT_LOGIN_ENDPOINT")
    def "Request accept authentication with invalid session cookie: #reason"() {
        given:
        authenticateToPolling(flow)

        when: "request accept authentication with invalid session cookie"
        Response response = given()
                .relaxedHTTPSValidation()
                .cookies(cookie)
                .post(flow.loginService.fullAuthAcceptUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(403))
        assertThat('Correct Content-Type', response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_FORBIDDEN))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_FORBIDDEN_REQUEST))
        assertThat("Incident number is present", response.jsonPath().getString("incident_nr"), hasLength(32))

        where:
        cookie                        | reason
        [:]                           | "no cookie"
        ["__Host-SESSION": null]      | "empty cookie"
        ["__Host-SESSION": "1234567"] | "incorrect cookie value"
    }

    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "OIDC login verifier request after rejecting authentication returns correct error in URL"() {
        given:
        authenticateToPolling(flow)
        Response response = Requests.getRequestWithParams(flow, flow.loginService.fullAuthRejectUrl, [error_code: REJECT_ERROR_CODE])

        when: "OIDC login verifier request after rejecting authentication"
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
        authenticateToPolling(flow)

        when:
        Response response = Requests.getRequestWithParams(flow, flow.loginService.fullAuthRejectUrl, [error_code: REJECT_ERROR_CODE])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(302))
        Steps.verifyResponseHeaders(response)
    }

    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "Request reject authentication with invalid error_code value"() {
        given:
        authenticateToPolling(flow)

        when:
        Response response = Requests.getRequestWithParams(flow, flow.loginService.fullAuthRejectUrl, [error_code: "ERROR12345"])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString("message"), is("authReject.errorCode: the only supported value is: \'user_cancel\'"))
        assertThat("Incident number is present", response.jsonPath().getString("incident_nr"), hasLength(32))
    }

    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "Request reject authentication with invalid session cookie"() {
        given:
        authenticateToPolling(flow)

        when: "reject authentication with invalid session cookie"
        Response response = given()
                .relaxedHTTPSValidation()
                .cookies(cookie)
                .param("error_code", REJECT_ERROR_CODE)
                .get(flow.loginService.fullAuthRejectUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString("message"), is(MESSAGE_SESSION_NOT_FOUND))

        where:
        cookie                        | reason
        [:]                           | "no cookie"
        ["__Host-SESSION": null]      | "empty cookie"
        ["__Host-SESSION": "1234567"] | "incorrect cookie value"
    }

    //TODO: AUT-630
    def "Authentication rejection request with invalid request type should fail: #requestType"() {
        given:
        authenticateToPolling(flow)

        when: "reject authentication with invalid request type"
        Response response = given()
                .relaxedHTTPSValidation()
                .cookies("__Host-SESSION": flow.sessionId)
                .params([error_code: REJECT_ERROR_CODE,
                         _csrf     : flow.csrf])
                .request(requestType, flow.loginService.fullAuthRejectUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString('message'), is(MESSAGE_INTERNAL_ERROR))

        where:
        requestType | _
        "POST"      | _
        "PUT"       | _
        "PATCH"     | _
        "DELETE"    | _
    }

    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "Request reject authentication with multiple error_code values"() {
        given:
        authenticateToPolling(flow)

        when: "Reject authentication with multiple error_code values"
        Response response = given()
                .relaxedHTTPSValidation()
                .cookies(["__Host-SESSION": flow.sessionId])
                .params(error_code: ["ERROR12345", "user_cancel"])
                .get(flow.loginService.fullAuthRejectUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString('message'), is(MESSAGE_DUPLICATE_PARAMETERS))
        assertThat("Incident number is present", response.jsonPath().getString("incident_nr"), hasLength(32))
    }

    @Step("Authentication flow up to Mobile-ID polling")
    private static authenticateToPolling(Flow flow) {
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, "60001017869", "68000769")
        Steps.pollMidResponse(flow)
    }
}
