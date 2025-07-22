package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import ee.ria.tara.model.ErrorMessage
import ee.ria.tara.model.OidcError
import ee.ria.tara.util.ErrorValidator
import io.qameta.allure.Feature
import io.qameta.allure.Issue
import io.qameta.allure.Step
import io.restassured.filter.cookie.CookieFilter
import io.restassured.http.Method
import io.restassured.response.Response
import org.apache.http.HttpStatus

import static io.restassured.RestAssured.given
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.hasLength
import static org.hamcrest.Matchers.startsWith
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.not
import static org.hamcrest.Matchers.containsString

class AuthenticationSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Feature("AUTHENTICATION")
    def "Request authentication with Mobile-ID: #certificate certificate chain"() {
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
        certificate                           | idCode        | phoneNumber || subject
        "TEST of ESTEID-SK 2015"              | "60001017716" | "69100366"  || "EE" + idCode
        "TEST of EID-SK 2016"                 | "60001017869" | "68000769"  || "EE" + idCode
        "TEST of SK ID Solutions EID-Q 2021E" | "51307149560" | "69930366"  || "EE" + idCode
    }

    @Feature("AUTHENTICATION")
    def "Request authentication with Smart-ID: #certificate certificate chain"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Response midAuthResponse = Steps.authenticateWithSid(flow, idCode)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience[0], is(flow.oidcClientPublic.clientId))
        assertThat("Correct subject", claims.subject, is(subject))

        where:
        certificate                           | idCode        || subject
        "TEST of EID-SK 2016"                 | "40404049996" || "EE" + idCode
        "TEST of SK ID Solutions EID-Q 2024E" | "40504040001" || "EE" + idCode
    }

    @Feature("AUTHENTICATION")
    @Feature("MID_AUTH_INIT_REQUEST")
    def "Authenticate with Mobile-ID with custom relying party name and UUID"() {
        given:
        Steps.startAuthenticationInTaraWithClient(flow, "SysTest-Relying-Party-client", "secret", "https://rp-client.test/oauth/response")
        Response sidAuthResponse = Steps.authenticateWithMid(flow, "60001017869", "68000769")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, sidAuthResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponseWithClient(flow, authenticationFinishedResponse, "SysTest-Relying-Party-client", "secret", "https://rp-client.test/oauth/response")
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience[0], is("SysTest-Relying-Party-client"))
        assertThat("Correct subject", claims.subject, is("EE60001017869"))
    }

    @Feature("AUTHENTICATION")
    def "Request authentication with Smart-ID"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Response sidAuthResponse = Steps.authenticateWithSid(flow, "40404049996")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, sidAuthResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience[0], is(flow.oidcClientPublic.clientId))
        assertThat("Correct subject", claims.subject, is("EE40404049996"))
    }

    @Feature("AUTHENTICATION")
    @Feature("SID_AUTH_INIT_REQUEST")
    def "Authenticate with Smart-ID with custom relying party name and UUID"() {
        given:
        Steps.startAuthenticationInTaraWithClient(flow, "SysTest-Relying-Party-client", "secret", "https://rp-client.test/oauth/response")
        Response sidAuthResponse = Steps.authenticateWithSid(flow, "40404049996")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, sidAuthResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponseWithClient(flow, authenticationFinishedResponse, "SysTest-Relying-Party-client", "secret", "https://rp-client.test/oauth/response")
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience[0], is("SysTest-Relying-Party-client"))
        assertThat("Correct subject", claims.subject, is("EE40404049996"))
    }

    @Feature("https://e-gov.github.io/TARA-Doku/TechnicalSpecification#41-authentication-request")
    def "Authentication request with #acrValues acr_values and with clients minimum_acr_value undefined defaults to acr '#defaultAcr'"() {
        given:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "openid")
        if (acrValues == "undefined") {
            paramsMap.remove("acr_values")
        } else {
            paramsMap << [acr_values: acrValues]
        }

        when:
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        Steps.createLoginSession(flow, initOIDCServiceSession)

        Response tokenResponse = Steps.authenticateWithWebEid(flow)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get('id_token')).JWTClaimsSet


        then:
        assertThat("Correct acr value", claims.getClaim("acr"), is(defaultAcr))

        where:
        acrValues   | defaultAcr
        "undefined" | "high"
        null        | "high"
    }

    @Feature("AUTHENTICATION")
    def "Eidas authentication #loa Loa request with minimum_acr_value undefined and with acr_values parameter '#acrValues'"() {
        given:
        Steps.startAuthenticationInTaraWithAcr(flow, acrValues)

        Response authenticationFinishedResponse = EidasSteps.initAuthenticationSessionGetFinishedResponse(flow,loa)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience[0], is(flow.oidcClientPublic.clientId))
        assertThat("Correct acr", claims.claims["acr"], is(acrClaim))
        assertThat("Correct subject", claims.subject, is("CA12345"))

        where:
        acrValues     | loa                  || acrClaim
        "low"         | EIDASLOA_LOW         || "low"
        "low"         | EIDASLOA_SUBSTANTIAL || "substantial"
        "low"         | EIDASLOA_HIGH        || "high"
        "substantial" | EIDASLOA_SUBSTANTIAL || "substantial"
        "substantial" | EIDASLOA_HIGH        || "high"
        "high"        | EIDASLOA_HIGH        || "high"
    }

    @Feature("AUTHENTICATION")
    def "Eidas authentication with Loa '#loa' succeeds with both minimum_acr_value and acr_values equal to #minimumAcrValue"() {
        given:
        String clientId = "client-mock-acr-$minimumAcrValue"
        String clientResponseUrl = "https://client.mock.acr.${minimumAcrValue}.localhost/oauth/response"
        String clientSecret = "secret"

        Map paramsMap = OpenIdUtils.getAuthorizationParametersWithClient(flow, clientId, clientSecret, clientResponseUrl)
        paramsMap << [acr_values: minimumAcrValue]

        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        Steps.createLoginSession(flow, initOIDCServiceSession)

        Response authenticationFinishedResponse = EidasSteps.initAuthenticationSessionGetFinishedResponse(flow,loa)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponseWithClient(flow, authenticationFinishedResponse, clientId, clientSecret, clientResponseUrl)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience[0], is(clientId))
        assertThat("Correct acr", claims.claims["acr"], is(acrClaim))
        assertThat("Correct subject", claims.subject, is("CA12345"))

        where:
        loa                  | minimumAcrValue || acrClaim
        EIDASLOA_LOW         | "low"           || "low"
        EIDASLOA_SUBSTANTIAL | "low"           || "substantial"
        EIDASLOA_HIGH        | "low"           || "high"
        EIDASLOA_SUBSTANTIAL | "substantial"   || "substantial"
        EIDASLOA_HIGH        | "substantial"   || "high"
        EIDASLOA_HIGH        | "high"          || "high"
    }

    @Feature("AUTHENTICATION")
    def "Authentication request with undefined acr_values defaults to minimum_acr_value '#minimumAcrValue' and succeeds for eIDAS LoA '#loa'"() {
        given:
        String clientId = "client-mock-acr-$minimumAcrValue"
        String clientResponseUrl = "https://client.mock.acr.${minimumAcrValue}.localhost/oauth/response"
        String clientSecret = "secret"

        Map paramsMap = OpenIdUtils.getAuthorizationParametersWithClient(flow, clientId, clientSecret, clientResponseUrl)
        paramsMap.remove("acr_values")

        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        Steps.createLoginSession(flow, initOIDCServiceSession)

        Response authenticationFinishedResponse = EidasSteps.initAuthenticationSessionGetFinishedResponse(flow,loa)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponseWithClient(flow, authenticationFinishedResponse, clientId, clientSecret, clientResponseUrl)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience[0], is(clientId))
        assertThat("Correct acr", claims.claims["acr"], is(acrClaim))
        assertThat("Correct subject", claims.subject, is("CA12345"))

        where:
        loa                  | minimumAcrValue || acrClaim
        EIDASLOA_LOW         | "low"           || "low"
        EIDASLOA_SUBSTANTIAL | "low"           || "substantial"
        EIDASLOA_HIGH        | "low"           || "high"
        EIDASLOA_SUBSTANTIAL | "substantial"   || "substantial"
        EIDASLOA_HIGH        | "substantial"   || "high"
        EIDASLOA_HIGH        | "high"          || "high"
    }

    @Feature("AUTHENTICATION")
    def "Eidas authentication #loa Loa request succeeds with minimum_acr_value undefined and with acr_values undefined"() {
        given:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap.remove("acr_values")

        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        Steps.createLoginSession(flow, initOIDCServiceSession)

        Response authenticationFinishedResponse = EidasSteps.initAuthenticationSessionGetFinishedResponse(flow,loa)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience[0], is(flow.oidcClientPublic.clientId))
        assertThat("Correct acr", claims.claims["acr"], is(acrClaim))
        assertThat("Correct subject", claims.subject, is("CA12345"))

        where:
        loa                  | acrClaim
        EIDASLOA_SUBSTANTIAL | "substantial"
        EIDASLOA_HIGH        | "high"
    }

    @Feature("AUTHENTICATION")
    def "Eidas authentication with Loa '#loa' fails with acr_values undefined and minimum_acr_value equal to #minimumAcrValue"() {
        given:
        String clientId = "client-mock-acr-$minimumAcrValue"
        String clientResponseUrl = "https://client.mock.acr.${minimumAcrValue}.localhost/oauth/response"
        String clientSecret = "secret"

        Map paramsMap = OpenIdUtils.getAuthorizationParametersWithClient(flow, clientId, clientSecret, clientResponseUrl)
        paramsMap.remove("acr_values")

        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        Steps.createLoginSession(flow, initOIDCServiceSession)
        EidasSteps.initEidasAuthSession(flow, COUNTRY_CA)
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, loa)
        Response authorizationResponse = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)

        when:
        Response redirectionResponse = EidasSteps.eidasRedirectAuthorizationResponse(flow, authorizationResponse,false)

        then:
        redirectionResponse.then()
                .statusCode(400)
                .body(
                        "error", is("Bad Request"),
                        "message", is("Teie poolt valitud välisriigi autentimisvahend on teenuse " +
                        "poolt nõutust madalama autentimistasemega. Palun valige mõni muu autentimisvahend."))

        where:
        loa                  | minimumAcrValue
        EIDASLOA_LOW         | "substantial"
        EIDASLOA_LOW         | "high"
        EIDASLOA_SUBSTANTIAL | "high"
    }

    @Feature("AUTHENTICATION")
    def "Authentication request with acr_values '#acrValues' not matching clients minimum_acr_value '#minimumAcrValue' returns error"() {
        given:
        String clientId = "client-mock-acr-$minimumAcrValue"
        String clientResponseUrl = "https://client.mock.acr.${minimumAcrValue}.localhost/oauth/response"
        String clientSecret = "secret"

        Map paramsMap = OpenIdUtils.getAuthorizationParametersWithClient(flow, clientId, clientSecret, clientResponseUrl)
        paramsMap << [acr_values: acrValues]

        when:
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        Response initLogin = Steps.createLoginSession(flow, initOIDCServiceSession)

        then:
        initLogin.then()
                .statusCode(400)
                .body(
                        "error", is("Bad Request"),
                        "message", is("Ebakorrektne päring. Teenusel pole lubatud päringus määratud " +
                        "autentimistaseme (acr_values) väärtust kasutada."))

        where:
        minimumAcrValue | acrValues
        "low"           | "substantial"
        "low"           | "high"
        "substantial"   | "low"
        "substantial"   | "high"
        "high"          | "low"
        "high"          | "substantial"
    }

    @Feature("AUTHENTICATION")
    def "Eidas authentication with insufficient Loa '#loa' fails with both minimum_acr_value and acr_values equal to #acrValues"() {
        given:
        String clientId = "client-mock-acr-$acrValues"
        String clientResponseUrl = "https://client.mock.acr.${acrValues}.localhost/oauth/response"
        String clientSecret = "secret"

        Map paramsMap = OpenIdUtils.getAuthorizationParametersWithClient(flow, clientId, clientSecret, clientResponseUrl)
        paramsMap << [acr_values: acrValues]

        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        Steps.createLoginSession(flow, initOIDCServiceSession)
        EidasSteps.initEidasAuthSession(flow, COUNTRY_CA)

        when:
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, loa)
        Response authorizationResponse = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        Response redirectionResponse = EidasSteps.eidasRedirectAuthorizationResponse(flow, authorizationResponse, false)

        then:
        redirectionResponse.then()
                .statusCode(400)
                .body(
                        "error", is("Bad Request"),
                        "message", is("Teie poolt valitud välisriigi autentimisvahend on teenuse poolt " +
                        "nõutust madalama autentimistasemega. Palun valige mõni muu autentimisvahend."))

        where:
        loa                  | acrValues
        EIDASLOA_LOW         | "substantial"
        EIDASLOA_LOW         | "high"
        EIDASLOA_SUBSTANTIAL | "high"
    }

    @Feature("AUTHENTICATION")
    def "Eidas authentication with insufficient Loa '#loa' fails with minimum_acr_value undefined and acr_values #acrValues"() {
        given:
        Map paramsMap = OpenIdUtils.getAuthorizationParametersWithAcrValues(flow, acrValues)
        if (acrValues == "undefined") {
            paramsMap.remove("acr_values")
        }

        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        Steps.createLoginSession(flow, initOIDCServiceSession)
        EidasSteps.initEidasAuthSession(flow, COUNTRY_CA)

        when:
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, loa)
        Response authorizationResponse = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        Response redirectionResponse = EidasSteps.eidasRedirectAuthorizationResponse(flow, authorizationResponse, false)

        then:
        redirectionResponse.then()
                .statusCode(400)
                .body(
                        "error", is("Bad Request"),
                        "message", is("Teie poolt valitud välisriigi autentimisvahend on teenuse poolt " +
                        "nõutust madalama autentimistasemega. Palun valige mõni muu autentimisvahend."))

        where:
        loa                  | acrValues
        EIDASLOA_LOW         | "undefined"
        EIDASLOA_LOW         | "substantial"
        EIDASLOA_LOW         | "high"
        EIDASLOA_SUBSTANTIAL | "high"
    }

    @Feature("https://e-gov.github.io/TARA-Doku/TechnicalSpecification#41-authentication-request")
    @Feature("TECHNICAL_ERRORS")
    def "Authentication request with invalid acr_values parameter value '#acrValues'"() {
        given:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "openid")
        paramsMap << [acr_values: acrValues]
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)

        when:
        Response response = Steps.followRedirect(flow, initOIDCServiceSession)

        then:
        response.then()
                .statusCode(500)
                .contentType("application/json;charset=UTF-8")
                .body("message", is(MESSAGE_INTERNAL_ERROR))

        where:
        acrValues | _
        "null"    | _
        "medium"  | _
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
        ErrorValidator.validate(redirectionResponse, ErrorMessage.EIDAS_INCORRECT_LOA)
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
                .cookies("__Host-SESSION": flow.sessionId)
                .params([_csrf: flow.csrf])
                .request(requestType, flow.loginService.fullAuthAcceptUrl)

        then:
        ErrorValidator.validate(response, ErrorMessage.INTERNAL_ERROR)

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
                .cookies(cookie)
                .post(flow.loginService.fullAuthAcceptUrl)

        then:
        ErrorValidator.validate(response, ErrorMessage.INVALID_CSRF_TOKEN)
        response.then().body("incident_nr", hasLength(32))

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
        Response response = Requests.getRequestWithParams(flow, flow.loginService.fullAuthRejectUrl, [error_code: OidcError.USER_CANCEL.code])

        when: "OIDC login verifier request after rejecting authentication"
        Response oidcServiceResponse = Steps.followRedirectWithCookies(flow, response, flow.oidcService.cookies)

        then:
        assertThat("Correct HTTP status code", oidcServiceResponse.statusCode, is(303))
        assertThat("Correct error in URL", oidcServiceResponse.header("location"), containsString(OidcError.USER_CANCEL.code))
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
        Response response = Requests.getRequestWithParams(flow, flow.loginService.fullAuthRejectUrl, [error_code: OidcError.USER_CANCEL.code])

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
        ErrorValidator.validate(response, HttpStatus.SC_BAD_REQUEST, "authReject.errorCode: the only supported value is: 'user_cancel'")
        response.then().body("incident_nr", hasLength(32))
    }

    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "Request reject authentication with invalid session cookie"() {
        given:
        authenticateToPolling(flow)

        when: "reject authentication with invalid session cookie"
        Response response = given()
                .cookies(cookie)
                .param("error_code", OidcError.USER_CANCEL.code)
                .get(flow.loginService.fullAuthRejectUrl)

        then:
        ErrorValidator.validate(response, ErrorMessage.SESSION_NOT_FOUND)

        where:
        cookie                        | reason
        [:]                           | "no cookie"
        ["__Host-SESSION": null]      | "empty cookie"
        ["__Host-SESSION": "1234567"] | "incorrect cookie value"
    }

    @Issue("AUT-630")
    def "Authentication rejection request with invalid request type should fail: #requestType"() {
        given:
        authenticateToPolling(flow)

        when: "reject authentication with invalid request type"
        Response response = given()
                .cookies("__Host-SESSION": flow.sessionId)
                .params([error_code: OidcError.USER_CANCEL.code,
                         _csrf     : flow.csrf])
                .request(requestType, flow.loginService.fullAuthRejectUrl)

        then:
        ErrorValidator.validate(response, ErrorMessage.INTERNAL_ERROR)

        where:
        requestType   | _
        Method.POST   | _
        Method.PUT    | _
        Method.PATCH  | _
        Method.DELETE | _
    }

    @Feature("AUTH_REJECT_LOGIN_ENDPOINT")
    def "Request reject authentication with multiple error_code values"() {
        given:
        authenticateToPolling(flow)

        when: "Reject authentication with multiple error_code values"
        Response response = given()
                .cookies(["__Host-SESSION": flow.sessionId])
                .params(error_code: ["ERROR12345", "user_cancel"])
                .get(flow.loginService.fullAuthRejectUrl)

        then:
        ErrorValidator.validate(response, ErrorMessage.DUPLICATE_PARAMETERS)
        response.then().body("incident_nr", hasLength(32))
    }

    @Step("Authentication flow up to Mobile-ID polling")
    private static authenticateToPolling(Flow flow) {
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, "60001017869", "68000769")
        Steps.pollMidResponse(flow)
    }
}
