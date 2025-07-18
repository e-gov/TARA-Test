package ee.ria.tara

import com.nimbusds.jwt.JWTClaimsSet
import ee.ria.tara.model.ErrorMessage
import ee.ria.tara.util.ErrorValidator
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import com.nimbusds.jose.jwk.JWKSet

import static org.hamcrest.Matchers.allOf
import static org.hamcrest.Matchers.endsWith
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.startsWith
import static org.hamcrest.MatcherAssert.assertThat

class OpenIdConnectSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Feature("OPENID_CONNECT")
    def "Metadata and token key ID matches"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Response midAuthResponse = Steps.authenticateWithMid(flow, "60001017727", "69200366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        String keyID = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).header.getKeyID()

        then:
        assertThat("Correct HTTP status code", tokenResponse.statusCode, is(200))
        assertThat("Correct key", keyID, is(flow.jwkSet.keys[0].getKeyID()))
    }

    @Feature("OPENID_CONNECT")
    def "Request with empty scope"() {
        given:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap << [scope: null]
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)

        when:
        Response initLoginSession = Steps.followRedirect(flow, initOIDCServiceSession)

        then:
        ErrorValidator.validate(initLoginSession, ErrorMessage.MISSING_SCOPE)
        initLoginSession.then().body("path", is("/auth/init"))
    }

    @Feature("OPENID_CONNECT")
    def "Request with invalid authorization code"() {
        given:
        Response initOIDCServiceSession = Steps.startAuthenticationInOidc(flow)
        Steps.createLoginSession(flow, initOIDCServiceSession)
        Response midAuthResponse = Steps.authenticateWithMid(flow, "60001017727", "69200366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        String authorizationCode = Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "code")

        when:
        Response response = Requests.webTokenBasicRequest(flow, authorizationCode + "e")

        then:
        assertThat("Correct status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_GRANT))
    }

    @Feature("OPENID_CONNECT")
    def "Request with missing parameter #paramName"() {
        given:
        Map formParamsMap = ["grant_type"  : "code",
                             "code"        : "1234567",
                             "redirect_uri": flow.oidcClientPublic.fullResponseUrl]

        formParamsMap.remove(paramName)

        when:
        Response response = Requests.getWebTokenResponseBody(flow, formParamsMap)

        then:
        assertThat("Correct status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString("error"), is(ERROR_REQUEST))
        assertThat("Correct error description", response.jsonPath().getString("error_description"), allOf(startsWith(errorSuffix), endsWith(errorPrefix)))

        where:
        paramName      || errorSuffix                                   | errorPrefix
        "code"         || "The request is missing a required parameter" | "whitelisted the redirect_uri you specified."
        "grant_type"   || "The request is missing a required parameter" | "Request parameter 'grant_type' is missing"
        "redirect_uri" || "The request is missing a required parameter" | "whitelisted the redirect_uri you specified."
    }


    @Feature("OPENID_CONNECT")
    def "Request with invalid parameter value #parameter"() {
        given:
        Map paramsMap = ["grant_type"  : "code",
                         "code"        : "1234567",
                         "redirect_uri": flow.oidcClientPublic.fullResponseUrl]

        paramsMap << parameter

        when:
        Response response = Requests.getWebTokenResponseBody(flow, paramsMap)

        then:
        assertThat("Correct status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString("error"), is(ERROR_REQUEST))
        assertThat("Correct error description", response.jsonPath().getString("error_description"), allOf(startsWith(errorSuffix), endsWith(errorPrefix)))

        where:
        parameter                                 || errorSuffix                                   | errorPrefix
        [redirect_uri: "https://www.example.com"] || "The request is missing a required parameter" | "whitelisted the redirect_uri you specified."
        [grant_type: "token"]                     || "The request is missing a required parameter" | "whitelisted the redirect_uri you specified."
        [code: "45678"]                           || "The request is missing a required parameter" | "whitelisted the redirect_uri you specified."
    }

    @Feature("OPENID_CONNECT")
    def "Request with url encoded state and nonce"() {
        given:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        flow.setState("testȺ田\uD83D\uDE0D&additional=1 %20")
        flow.setNonce("testȺ田\uD83D\uDE0D&additional=1 %20")
        paramsMap << [state: flow.state, nonce: flow.nonce]
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        Steps.createLoginSession(flow, initOIDCServiceSession)
        Response midAuthResponse = Steps.authenticateWithMid(flow, "60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct nonce", claims.getClaim("nonce"), is(paramsMap.get("nonce")))
        assertThat("Correct state", claims.getClaim("state"), is(paramsMap.get("state")))
    }

}
