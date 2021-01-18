package ee.ria.tara

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Ignore;
import spock.lang.Unroll
import com.nimbusds.jose.jwk.JWKSet

import java.nio.charset.StandardCharsets
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.startsWith
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat

class OpenIdConnectSpec extends TaraSpecification {
    Flow flow = new Flow(props)
    String DEFAULT_SCOPE = "openid"

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Unroll
    @Feature("OPENID_CONNECT")
    def "Metadata and token key ID matches"() {
        expect:
        Response oidcServiceResponse = Steps.initAuthSessionAndAuthWithMobileID(flow)
        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        assertEquals("Correct HTTP status code is returned", 200, consentResponse.statusCode())
        Response consentConfirmResponse = Steps.consentConfirmation(flow, true)
        assertEquals("Correct HTTP status code is returned", 302, consentConfirmResponse.statusCode())
        assertThat(consentConfirmResponse.getHeader("location"), startsWith(flow.oidcService.fullAuthenticationRequestUrl))

        Response webTokenResponse = Steps.getWebTokenFromOidcService(flow, consentConfirmResponse)
        Map<String, String> webToken = webTokenResponse.body().jsonPath().getMap("\$.")
        String keyID = Steps.verifyTokenAndReturnSignedJwtObject(flow, webToken.get("id_token")).getHeader().getKeyID()
        assertThat(keyID, equalTo(flow.jwkSet.getKeys().get(0).getKeyID()))
    }

    @Unroll
    @Feature("OPENID_CONNECT")
    def "Request a token twice"() {
        expect:
        Response oidcServiceResponse = Steps.initAuthSessionAndAuthWithMobileID(flow)
        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        assertEquals("Correct HTTP status code is returned", 200, consentResponse.statusCode())
        Response consentConfirmResponse = Steps.consentConfirmation(flow, true)
        assertEquals("Correct HTTP status code is returned", 302, consentConfirmResponse.statusCode())
        assertThat(consentConfirmResponse.getHeader("location"), startsWith(flow.oidcService.fullAuthenticationRequestUrl))
        Response oidcServiceResponse2 = Steps.followRedirectWithCookies(flow, consentConfirmResponse, flow.oidcService.cookies)
        assertEquals("Correct HTTP status code is returned", 302, oidcServiceResponse2.statusCode())
        // 1
        Response webTokenResponse = Steps.followRedirectWithCookies(flow, oidcServiceResponse2, flow.oidcClient.cookies)
        assertEquals("Correct HTTP status code is returned", 200, webTokenResponse.statusCode())
        // 2
        Response webTokenResponse2 = Steps.followRedirectWithCookies(flow, oidcServiceResponse2, flow.oidcClient.cookies)
        assertEquals("Correct HTTP status code is returned", 200, webTokenResponse2.statusCode())
        assertThat("Correct Content-Type is returned", webTokenResponse2.getContentType(), startsWith("application/json"))
        assertEquals("Correct error message is returned", "invalid_grant", webTokenResponse2.body().jsonPath().get("error"))
    }

    @Ignore // Etapp 4
    @Unroll
    @Feature("OPENID_CONNECT")
    def "Request with empty scope"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap.put("scope", "")
        Response response = Requests.getRequestWithParams(flow, flow.oidcService.fullAuthenticationRequestUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        assertEquals("Correct error value", " error text here", Utils.getParamValueFromResponseHeader(response, "error"))
    }

    @Unroll
    @Feature("OPENID_CONNECT")
    def "Request with invalid authorization code"() {
        expect:
        Response oidcServiceResponse = Steps.initAuthSessionAndAuthWithMobileID(flow)
        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        assertEquals("Correct HTTP status code is returned", 200, consentResponse.statusCode())
        Response consentConfirmResponse = Steps.consentConfirmation(flow, true)
        assertEquals("Correct HTTP status code is returned", 302, consentConfirmResponse.statusCode())
        assertThat(consentConfirmResponse.getHeader("location"), startsWith(flow.oidcService.fullAuthenticationRequestUrl))
        Response oidcServiceResponse2 = Steps.followRedirectWithCookies(flow, consentConfirmResponse, flow.oidcService.cookies)
        assertEquals("Correct HTTP status code is returned", 302, oidcServiceResponse2.statusCode())

        HashMap<String, String> paramsMap = (HashMap)Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "scope", DEFAULT_SCOPE)
        def map2 = Utils.setParameter(paramsMap, "state", flow.state)
        def map4 = Utils.setParameter(paramsMap, "code", Utils.getParamValueFromResponseHeader(oidcServiceResponse2, "code") + "e")
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.oidcClient.fullResponseUrl, flow.oidcClient.cookies, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())
        assertThat("Correct Content-Type is returned", response.getContentType(), startsWith("application/json"))
        assertEquals("Correct error message is returned", "invalid_grant", response.body().jsonPath().get("error"))
    }

    @Unroll
    @Feature("OPENID_CONNECT")
    def "Request with missing authorization code"() {
        expect:
        Response oidcServiceResponse = Steps.initAuthSessionAndAuthWithMobileID(flow)
        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        assertEquals("Correct HTTP status code is returned", 200, consentResponse.statusCode())
        Response consentConfirmResponse = Steps.consentConfirmation(flow, true)
        assertEquals("Correct HTTP status code is returned", 302, consentConfirmResponse.statusCode())
        assertThat(consentConfirmResponse.getHeader("location"), startsWith(flow.oidcService.fullAuthenticationRequestUrl))
        Response oidcServiceResponse2 = Steps.followRedirectWithCookies(flow, consentConfirmResponse, flow.oidcService.cookies)
        assertEquals("Correct HTTP status code is returned", 302, oidcServiceResponse2.statusCode())

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "scope", DEFAULT_SCOPE)
        def map2 = Utils.setParameter(paramsMap, "state", flow.state)

        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.oidcClient.fullResponseUrl, flow.oidcClient.cookies, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())
        assertThat("Correct Content-Type is returned", response.getContentType(), startsWith("application/json"))
        assertEquals("Correct error message is returned", "invalid_grant", response.body().jsonPath().get("error"))
    }

    @Unroll
    @Feature("OPENID_CONNECT")
    def "Request with missing parameter #paramName"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap.remove(paramName)
        Response response = Requests.getRequestWithParams(flow, flow.oidcService.fullAuthenticationRequestUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", statusCode, response.statusCode())
        assertEquals("Correct error value", error, Utils.getParamValueFromResponseHeader(response, "error"))
        String actualErrorDescription = URLDecoder.decode(Utils.getParamValueFromResponseHeader(response, "error_description"), StandardCharsets.UTF_8)
        assertThat("Correct error_description value", actualErrorDescription, startsWith(errorDescription))
        String actualErrorHint = URLDecoder.decode(Utils.getParamValueFromResponseHeader(response, "error_hint"), StandardCharsets.UTF_8)
        assertThat("Correct error_hint value", actualErrorHint, startsWith(errorHint))

        where:
        paramName       || statusCode || error                       || errorDescription                                                                                                              || errorHint
        "client_id"     || 302        || "invalid_client"            || "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method" || "The requested OAuth 2.0 Client does not exist."
        "response_type" || 302        || "unsupported_response_type" || "The authorization server does not support obtaining a token using this method"                                               || "The request is missing the \"response_type\"\" parameter"
        "state"         || 302        || "invalid_state"             || "The state is missing or does not have enough characters and is therefore considered too weak"                                || "Request parameter \"state\" must be at least be 8 characters long to ensure sufficient entropy"
     //   "nonce"         || 302        || "invalid_state"             || "The state is missing or does not have enough characters and is therefore considered too weak"                                || "Request parameter \"state\" must be at least be 8 characters long to ensure sufficient entropy"

    }

    @Unroll
    @Feature("OPENID_CONNECT")
    def "Request with invalid parameter value #paramName"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap.put(paramName, paramValue)
        Response response = Requests.getRequestWithParams(flow, flow.oidcService.fullAuthenticationRequestUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", statusCode, response.statusCode())
        assertEquals("Correct error value", error, Utils.getParamValueFromResponseHeader(response, "error"))
        String actualErrorDescription = URLDecoder.decode(Utils.getParamValueFromResponseHeader(response, "error_description"), StandardCharsets.UTF_8)
        assertThat("Correct error_description value", actualErrorDescription, startsWith(errorDescription))
        String actualErrorHint = URLDecoder.decode(Utils.getParamValueFromResponseHeader(response, "error_hint"), StandardCharsets.UTF_8)
        assertThat("Correct error_hint value", actualErrorHint, startsWith(errorHint))

        where:
        paramName       | paramValue                         || statusCode || error                       || errorDescription                                                                                                                                   || errorHint
        "client_id"     | "my-old-client"                    || 302        || "invalid_client"            || "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method"                      || "The requested OAuth 2.0 Client does not exist."
        "scope"         | "wrongscope"                       || 302        || "invalid_scope"             || "The requested scope is invalid, unknown, or malformed"                                                                                            || "The OAuth 2.0 Client is not allowed to request scope"
        "response_type" | "token"                            || 302        || "unsupported_response_type" || "The authorization server does not support obtaining a token using this method"                                                                    || "The client is not allowed to request response_type \"token"
        "redirect_uri"  | "https://www.example.com/redirect" || 302        || "invalid_request"           || "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed" || "The \"redirect_uri\" parameter does not match any of the OAuth 2.0 Client's pre-registered redirect urls"
        "state"         | "short"                            || 302        || "invalid_state"             || "The state is missing or does not have enough characters and is therefore considered too weak"                                                     || "Request parameter \"state\" must be at least be 8 characters long to ensure sufficient entropy."
        // Uurida max pikkust    "state" | RandomStringUtils.random(4000, true, true) || 302 || "invalid_state" || "The state is missing or does not have enough characters and is therefore considered too weak" || "Request parameter \"state\" must be at least be 8 characters long to ensure sufficient entropy."
        // Uurida max ja min pikkust     "nonce" | RandomStringUtils.random(4000, true, true) || 302 || "invalid_nonce" || "The state is missing or does not have enough characters and is therefore considered too weak" || "Request parameter \"state\" must be at least be 8 characters long to ensure sufficient entropy."

    }

    @Unroll
    @Feature("OPENID_CONNECT")
    def "Request with url encoded state and nonce"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap.put("state", "testȺ田\uD83D\uDE0D&additional=1 %20")
        paramsMap.put("nonce", "testȺ田\uD83D\uDE0D&additional=1 %20")
        Response initOIDCServiceSession = Steps.createOIDCSessionWithParameters(flow, paramsMap)
        Response initLoginSession = Steps.createLoginSession(flow, initOIDCServiceSession)
        assertEquals("Correct HTTP status code is returned", 200, initLoginSession.statusCode())
        Response oidcServiceResponse = Steps.authWithMobileID(flow)
        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        assertEquals("Correct HTTP status code is returned", 200, consentResponse.statusCode())
        Response consentConfirmResponse = Steps.consentConfirmation(flow, true)
        assertEquals("Correct HTTP status code is returned", 302, consentConfirmResponse.statusCode())

        Response oidcServiceResponse2 = Steps.followRedirectWithCookies(flow, consentConfirmResponse, flow.oidcService.cookies)
        assertEquals("Correct HTTP status code is returned", 302, oidcServiceResponse2.statusCode())
        String authorizationCode = Utils.getParamValueFromResponseHeader(oidcServiceResponse2, "code")
        Response tokenResponse = Requests.getWebToken(flow, authorizationCode)
        assertEquals("Correct HTTP status code is returned", 200, tokenResponse.statusCode())
        Map<String, String> webToken = tokenResponse.body().jsonPath().getMap("\$.")
        JWTClaimsSet claims =  SignedJWT.parse(webToken.get("id_token")).getJWTClaimsSet();
        assertThat(claims.getClaim("nonce"), equalTo(paramsMap.get("nonce")))
        // Should be fixed in id_token
        // assertThat(claims.getClaim("state"), equalTo(paramsMap.get("state")))
    }

}
