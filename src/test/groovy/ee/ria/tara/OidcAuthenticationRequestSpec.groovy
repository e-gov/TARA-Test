package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import org.hamcrest.Matchers
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Unroll

import static org.hamcrest.CoreMatchers.is
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.startsWith
import static org.junit.jupiter.api.Assertions.*
import static org.hamcrest.MatcherAssert.assertThat


class OidcAuthenticationRequestSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Unroll
    @Feature("https://e-gov.github.io/TARA-Doku/TechnicalSpecification#41-authentication-request")
    def "Authentication request with invalid param values #paramName"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "openid")
        def value = paramsMap.put(paramName, paramValue)
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        assertEquals(statusCode, initOIDCServiceSession.statusCode(), "Correct HTTP status code is returned")
        assertEquals(error, Utils.getParamValueFromResponseHeader(initOIDCServiceSession, "error"), "Correct error message is returned")
        String errorDescription = Utils.getParamValueFromResponseHeader(initOIDCServiceSession, "error_description")
        assertThat("Correct error_description suffix", errorDescription, startsWith(errorSuffix))
        assertThat("Correct error_description preffix", errorDescription, Matchers.endsWith(errorPreffix))

        where:
        paramName       | paramValue                || statusCode || error                       || errorSuffix || errorPreffix
        "redirect_uri"  | "https://www.example.com" || 302        || "invalid_request"           || "The request is missing a required parameter" || "pre-registered redirect urls."
        "scope"         | "my_scope"                || 302        || "invalid_scope"             || "The requested scope is invalid" || " is not allowed to request scope 'my_scope'."
        "scope"         | "openid,eidas"            || 302        || "invalid_scope"             || "The requested scope is invalid" || " is not allowed to request scope 'openid,eidas'."
        "response_type" | "token"                   || 302        || "unsupported_response_type" || "The authorization server does not support obtaining a token" || "is not allowed to request response_type 'token'."
        "client_id"     | "my_client"               || 302        || "invalid_client"            || "Client authentication failed" || "The requested OAuth 2.0 Client does not exist."
    }

    @Unroll
    @Feature("https://e-gov.github.io/TARA-Doku/TechnicalSpecification#41-authentication-request")
    def "Authentication request with disabled scope for OIDC client"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParametersForSpecificProxyService(flow, "openid smartid")
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)

        String errorDescription= "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'smartid'."
        assertThat("Correct HTTP status code is returned", initOIDCServiceSession.statusCode() == 302)
        assertThat("Correct error message is returned", Utils.getParamValueFromResponseHeader(initOIDCServiceSession, "error") == "invalid_scope")
        assertThat("Correct error_description is returned", Utils.getParamValueFromResponseHeader(initOIDCServiceSession, "error_description") == errorDescription)
    }

    @Unroll
    @Feature("OIDC_LANGUAGE_SELECTION")
    def "Authentication request with different ui_locales: #label"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "openid")
        def value = Utils.setParameter(paramsMap, paramName, paramValue)
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        Response response = Steps.followRedirect(flow, initOIDCServiceSession)
        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        response.then().body("html.head.title", equalTo(expectedValue))

        where:
        paramName    | paramValue | label                                     || expectedValue
        "ui_locales" | "zu"       | "Fallback into default language et"       || "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        "ui_locales" | "et"       | "Estonian"                                || "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        "ui_locales" | "ru"       | "Russian"                                 || "Национальный сервис аутентификации - Для безопасной аутентификации в э-услугах"
        "ui_locales" | "en"       | "English"                                 || "National authentication service - Secure authentication for e-services"
        "ui_locales" | "fi ru en" | "Select first supported locale from list" || "Национальный сервис аутентификации - Для безопасной аутентификации в э-услугах"
        "ui_locales" | "ET"       | "Estonian with big letters"               || "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        "ui_locales" | "RU"       | "Russian with big letters"                || "Национальный сервис аутентификации - Для безопасной аутентификации в э-услугах"
        "ui_locales" | "EN"       | "English with big letters"                || "National authentication service - Secure authentication for e-services"
        "ui_locales" | _          | "Without locale parameter"                || "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
    }

    @Unroll
    @Feature("https://e-gov.github.io/TARA-Doku/TechnicalSpecification#41-authentication-request")
    def "Authentication request with unknown parameter"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "openid")
        def value = paramsMap.put("my_parameter", "654321")
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        assertEquals(302, initOIDCServiceSession.statusCode(), "Correct HTTP status code is returned")
        assertThat(initOIDCServiceSession.getHeader("location"), Matchers.containsString("?login_challenge="))
    }

    @Unroll
    @Feature("https://e-gov.github.io/TARA-Doku/TechnicalSpecification#41-authentication-request")
    @Feature("TECHNICAL_ERRORS")
    def "Authentication request with invalid acr_values parameter value"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "openid")
        def value = paramsMap.put("acr_values", "medium")
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        Response response = Steps.followRedirect(flow, initOIDCServiceSession)
        assertEquals(500, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertThat(response.body().jsonPath().get("message").toString(), startsWith("Autentimine ebaõnnestus teenuse tehnilise vea tõttu."))
    }

    @Unroll
    @Feature("OIDC_SCOPE_EMPTY")
    def "Authentication request with empty scope"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "")
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        Response response = Steps.followRedirect(flow, initOIDCServiceSession)
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertThat(response.body().jsonPath().get("message").toString(), startsWith("Päringus puudub scope parameeter."))
    }

    @Unroll
    @Feature("OIDC_SCOPE_IDCARD")
    @Feature("OIDC_SCOPE_MID")
    @Feature("OIDC_SCOPE_SMARTID")
    def "Authentication request with different scopes: #label"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "openid " + scopes)
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        Response response = Steps.followRedirect(flow, initOIDCServiceSession)
        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        assertThat("Correct ID-Card scope value", isIdCardPresent(response), is(idCard))
        assertThat("Correct MID scope value", isMidPresent(response), is(mID))
        assertThat("Correct Smart-ID scope value", isSmartIdPresent(response), is(smartID))

        where:
        scopes            | label                  || idCard || mID   || smartID
        "idcard"          | "with idcard"          || true   || false || false
        "mid"             | "with mid"             || false  || true  || false
        "smartid"         | "with smartid"         || false  || false || true

    }

    @Unroll
    @Feature("OIDC_SCOPE_EMAIL")
    @Feature("https://e-gov.github.io/TARA-Doku/TechnicalSpecification#41-authentication-request")
    def "Authentication request with email scope"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid email")
        Response idCardAuthResponse = Steps.authenticateWithIdCard(flow, "src/test/resources/joeorg-auth.pem")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, idCardAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo("idcard"))
        assertThat(claims.getClaim("email"), equalTo("38001085718@eesti.ee"))
        assertThat(claims.getClaim("email_verified"), equalTo(false))
    }

    @Unroll
    @Feature("OIDC_SCOPE_PHONE")
    @Feature("https://e-gov.github.io/TARA-Doku/TechnicalSpecification#41-authentication-request")
    def "Authentication request with phone scope"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid phone")
        Response midAuthResponse = Steps.authenticateWithMid(flow,"60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientPublic.clientId))
        assertThat(claims.getSubject(), equalTo("EE60001017716"))
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo("mID"))
        assertThat(claims.getClaim("phone_number"), equalTo("+37269100366"))
        assertThat(claims.getClaim("phone_number_verified"), equalTo(true))
    }

    @Unroll
    @Feature("https://e-gov.github.io/TARA-Doku/TechnicalSpecification#41-authentication-request")
    def "Authentication request with empty optional parameters: #paramName"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "openid")
        def value = Utils.setParameter(paramsMap, paramName, paramValue)
        if (paramName.equalsIgnoreCase("nonce")) {
            flow.setNonce("")
        }
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        Steps.createLoginSession(flow, initOIDCServiceSession)

        String certificate = Utils.getCertificateAsString("src/test/resources/joeorg-auth.pem")
        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(headersMap, "XCLIENTCERTIFICATE", certificate)
        Requests.idCardAuthentication(flow, headersMap)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)

        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)

        if (consentResponse.getStatusCode() == 200) {
            consentResponse = Steps.submitConsent(flow, true)
            assertEquals(302, consentResponse.statusCode(), "Correct HTTP status code is returned")
            Steps.verifyResponseHeaders(consentResponse)
        }
        Response oidcserviceResponse = Steps.followRedirectWithCookies(flow, consentResponse, flow.oidcService.cookies)
        Response sa = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        String authorizationCode = Utils.getParamValueFromResponseHeader(oidcserviceResponse, "code")
        Response tokenResponse = Requests.getWebToken(flow, authorizationCode)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientPublic.clientId))
        assertThat(claims.getSubject(), equalTo("EE38001085718"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("JAAK-KRISTJAN"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("family_name"), equalTo("JÕEORG"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("date_of_birth"), equalTo("1980-01-08"))
        assertThat(claims.getClaim("amr")[0].toString(), equalTo("idcard"))
        assertThat(claims.getClaim("acr"), equalTo("high"))

        where:
        paramName    | paramValue
        "ui_locales" | _
        "nonce" | _
        "acr_values" | _
        "redirect_uri" | _
    }

    @Unroll
    @Feature("https://e-gov.github.io/TARA-Doku/TechnicalSpecification#41-authentication-request")
    def "Authentication request with empty mandatory parameters: #paramName"() {
        expect:

        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "openid")
        def value = Utils.setParameter(paramsMap, paramName, paramValue)

        Response response = Requests.getRequestWithParams(flow, flow.oidcService.fullAuthenticationRequestUrl, value,  Collections.emptyMap())
        assertEquals(expectedErrorDescription ,Utils.getParamValueFromResponseHeader(response, "error_description"), "Error description parameter exists")

        where:
        paramName    | paramValue | expectedErrorDescription
        "state" | _ | "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy."
        "response_type" | _ | "The authorization server does not support obtaining a token using this method. `The request is missing the 'response_type' parameter."
        "client_id" | _ | "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist."
    }

}
