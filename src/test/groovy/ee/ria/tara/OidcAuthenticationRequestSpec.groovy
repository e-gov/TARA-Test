package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import ee.ria.tara.model.ErrorMessage
import ee.ria.tara.model.LoA
import ee.ria.tara.model.OidcError
import ee.ria.tara.util.ErrorValidator
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.http.HttpStatus

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*

class OidcAuthenticationRequestSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Feature("https://e-gov.github.io/TARA-Doku/TechnicalSpecification#41-authentication-request")
    def "Authentication request with invalid param values: #parameter"() {
        given:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "openid")
        paramsMap << parameter

        when:
        Response response = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(statusCode))
        assertThat("Correct error", Utils.getParamValueFromResponseHeader(response, "error"), is(error.code))
        assertThat("Correct error_description", Utils.getParamValueFromResponseHeader(response, "error_description"), allOf(startsWith(errorSuffix), endsWith(errorPrefix)))

        where:
        parameter                                 || statusCode | error                               | errorSuffix                                                   | errorPrefix
        [redirect_uri: "https://www.example.com"] || 302        | OidcError.INVALID_REQUEST           | "The request is missing a required parameter"                 | "pre-registered redirect urls."
        [scope: "my_scope"]                       || 303        | OidcError.INVALID_SCOPE             | "The requested scope is invalid"                              | " is not allowed to request scope 'my_scope'."
        [scope: "openid,eidas"]                   || 303        | OidcError.INVALID_SCOPE             | "The requested scope is invalid"                              | " is not allowed to request scope 'openid,eidas'."
        [response_type: "token"]                  || 303        | OidcError.UNSUPPORTED_RESPONSE_TYPE | "The authorization server does not support obtaining a token" | "is not allowed to request response_type 'token'."
        [client_id: "my_client"]                  || 302        | OidcError.INVALID_CLIENT            | "Client authentication failed"                                | "The requested OAuth 2.0 Client does not exist."
    }

    @Feature("https://e-gov.github.io/TARA-Doku/TechnicalSpecification#41-authentication-request")
    def "Authentication request with disabled scope for OIDC client"() {
        given:
        Map paramsMap = OpenIdUtils.getAuthorizationParametersForSpecificProxyService(flow, "openid smartid")

        when:
        Response response = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)

        then:
        String errorDescription = "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'smartid'."
        assertThat("Correct HTTP status code", response.statusCode, is(303))
        assertThat("Correct error", Utils.getParamValueFromResponseHeader(response, "error"), is(OidcError.INVALID_SCOPE.code))
        assertThat("Correct error description", Utils.getParamValueFromResponseHeader(response, "error_description"), is(errorDescription))
    }

    @Feature("OIDC_LANGUAGE_SELECTION")
    def "Authentication request with different ui_locales: #label"() {
        given:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "openid")
        paramsMap << parameter
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)

        when: "Initialize login request"
        Response response = Steps.followRedirect(flow, initOIDCServiceSession)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        assertThat("Correct HTML title", response.htmlPath().getString("html.head.title"), is(expectedValue))

        where:
        parameter                | label                                     || expectedValue
        [ui_locales: "zu"]       | "Fallback into default language et"       || "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        [ui_locales: "et"]       | "Estonian"                                || "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        [ui_locales: "ru"]       | "Russian"                                 || "Государственная услуга аутентификации - Для безопасной аутентификации в э-услугах"
        [ui_locales: "en"]       | "English"                                 || "State authentication service - Secure authentication for e-services"
        [ui_locales: "fi ru en"] | "Select first supported locale from list" || "Государственная услуга аутентификации - Для безопасной аутентификации в э-услугах"
        [ui_locales: "ET"]       | "Estonian with big letters"               || "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        [ui_locales: "RU"]       | "Russian with big letters"                || "Государственная услуга аутентификации - Для безопасной аутентификации в э-услугах"
        [ui_locales: "EN"]       | "English with big letters"                || "State authentication service - Secure authentication for e-services"
        [ui_locales: null]       | "Without locale parameter"                || "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
    }

    @Feature("https://e-gov.github.io/TARA-Doku/TechnicalSpecification#41-authentication-request")
    def "Authentication request with unknown parameter"() {
        given:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, 'openid')
        paramsMap << [my_parameter: "654321"]

        when:
        Response response = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(302))
        assertThat("Correct location header", response.header("location"), endsWith("?login_challenge=" + flow.loginChallenge))
    }

    @Feature("OIDC_SCOPE_EMPTY")
    def "Authentication request with empty scope"() {
        given:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "")
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)

        when:
        Response response = Steps.followRedirect(flow, initOIDCServiceSession)

        then:
        ErrorValidator.validate(response, ErrorMessage.MISSING_SCOPE)
    }

    @Feature("OIDC_SCOPE_IDCARD")
    @Feature("OIDC_SCOPE_MID")
    @Feature("OIDC_SCOPE_SMARTID")
    @Feature("OIDC_SCOPE_EIDAS")
    def "Authentication request with different scopes: #label"() {
        given:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "openid " + scopes)
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)

        when:
        Response response = Steps.followRedirect(flow, initOIDCServiceSession)

        def path = { val -> "**.findAll { it.'@data-tab' == '${val}' }.size()" }

        then:
        response.then()
                .statusCode(HttpStatus.SC_OK)
                .body(
                        path('smart-id'), smartID ? greaterThan(0) : equalTo(0),
                        path('id-card'), idCard ? greaterThan(0) : equalTo(0),
                        path('mobile-id'), mID ? greaterThan(0) : equalTo(0),
                        path('eu-citizen'), eidas ? greaterThan(0) : equalTo(0)
                )

        where:
        scopes    | label          || idCard | mID   | smartID | eidas
        "idcard"  | "with idcard"  || true   | false | false   | false
        "mid"     | "with mid"     || false  | true  | false   | false
        "smartid" | "with smartid" || false  | false | true    | false
        "eidas"   | "with eidas"   || false  | false | false   | true
    }

    @Feature("OIDC_SCOPE_EMAIL")
    @Feature("https://e-gov.github.io/TARA-Doku/TechnicalSpecification#41-authentication-request")
    def "Authentication request with email scope"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid email")

        when:
        Response tokenResponse = Steps.authenticateWithWebEid(flow)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct authentication method", claims.getStringArrayClaim("amr")[0], is("idcard"))
        assertThat("Correct email", claims.getClaim("email"), is("jaak-kristjan.joeorg@eesti.ee"))
        assertThat("Email_verified is false", claims.getClaim("email_verified"), is(false))
    }

    @Feature("OIDC_SCOPE_PHONE")
    @Feature("https://e-gov.github.io/TARA-Doku/TechnicalSpecification#41-authentication-request")
    def "Authentication request with phone scope"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid phone")
        Response midAuthResponse = Steps.authenticateWithMid(flow, "60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct authentication method", claims.getStringArrayClaim("amr")[0], is("mID"))
        assertThat("Correct phone number", claims.getClaim("phone_number"), is('+37269100366'))
        assertThat("Phone number is verified", claims.getClaim("phone_number_verified"), is(true))
    }

    @Feature("https://e-gov.github.io/TARA-Doku/TechnicalSpecification#41-authentication-request")
    def "Authentication request with empty optional parameters: #parameter"() {
        given:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "openid")
        paramsMap << parameter

        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        Steps.createLoginSession(flow, initOIDCServiceSession)

        when:
        Response tokenResponse = Steps.authenticateWithWebEid(flow)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get('id_token')).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience[0], is(ClientStore.mockPublic.clientId))
        assertThat("Correct subject", claims.subject, is("EE38001085718"))
        assertThat("Correct authentication method", claims.getStringArrayClaim("amr")[0], is("idcard"))
        assertThat("Correct LoA", claims.getClaim("acr"), is(LoA.HIGH.toString()))

        where:
        parameter            | paramValue
        [ui_locales: null]   | _
        [acr_values: null]   | _
        [redirect_uri: null] | _
    }

    @Feature("https://e-gov.github.io/TARA-Doku/TechnicalSpecification#41-authentication-request")
    def "Authentication request with empty mandatory parameters: #parameter"() {
        given:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "openid")
        paramsMap << parameter

        when:
        Response response = Requests.getRequestWithParams(flow, flow.oidcService.fullAuthorizationUrl, paramsMap)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(statusCode))
        assertThat("Correct error description", Utils.getParamValueFromResponseHeader(response, "error_description"), is(errorDescription))

        where:
        parameter             || statusCode | errorDescription
        [state: null]         || 303        | "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy."
        [response_type: null] || 303        | "The authorization server does not support obtaining a token using this method. `The request is missing the 'response_type' parameter."
        [client_id: null]     || 302        | "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist."
    }
}
