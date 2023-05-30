package ee.ria.tara

import com.nimbusds.jwt.JWTClaimsSet
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
    Flow flow = new Flow(props)

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
    def "Request a token twice"() {
        given:
        Response initOIDCServiceSession = Steps.startAuthenticationInOidc(flow)
        Steps.createLoginSession(flow, initOIDCServiceSession)
        Response midAuthResponse = Steps.authenticateWithMid(flow, "60001017727", "69200366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        String authorizationCode = Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "code")
        // 1
        Requests.getWebToken(flow, authorizationCode)

        when:
        // 2
        Response tokenResponse2 = Requests.getWebToken(flow, authorizationCode)

        then:
        assertThat("Correct HTTP status code", tokenResponse2.statusCode, is(400))
        assertThat("Correct Content-Type", tokenResponse2.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", tokenResponse2.jsonPath().getString("error"), is(ERROR_GRANT))
        assertThat("Correct error description", tokenResponse2.jsonPath().getString("error_description"), endsWith("The authorization code has already been used."))
    }

    @Feature("OPENID_CONNECT")
    def "Request with empty scope"() {
        given:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap.put("scope", "")
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)

        when:
        Response initLoginSession = Steps.followRedirect(flow, initOIDCServiceSession)

        then:
        assertThat("Correct status code", initLoginSession.statusCode, is(400))
        assertThat("Correct error", initLoginSession.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", initLoginSession.jsonPath().getString("message"), is("Päringus puudub scope parameeter."))
        assertThat("Correct path", initLoginSession.jsonPath().getString("path"), is("/auth/init"))
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
        Response response = Requests.getWebToken(flow, authorizationCode + "e")

        then:
        assertThat("Correct status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_GRANT))
    }

    @Feature("OPENID_CONNECT")
    def "Request with missing parameter #paramName"() {
        given:
        Map formParamsMap = [
                "grant_type"  : "code",
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
    def "Request with invalid parameter value #paramName"() {
        given:
        Map formParamsMap = [
                "grant_type"  : "code",
                "code"        : "1234567",
                "redirect_uri": flow.oidcClientPublic.fullResponseUrl,
                paramName     : paramValue]

        when:
        Response response = Requests.getWebTokenResponseBody(flow, formParamsMap)

        then:
        assertThat("Correct status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString("error"), is(ERROR_REQUEST))
        assertThat("Correct error description", response.jsonPath().getString("error_description"), allOf(startsWith(errorSuffix), endsWith(errorPrefix)))

        where:
        paramName      | paramValue                || errorSuffix                                   | errorPrefix
        "redirect_uri" | "https://www.example.com" || "The request is missing a required parameter" | "whitelisted the redirect_uri you specified."
        "grant_type"   | "token"                   || "The request is missing a required parameter" | "whitelisted the redirect_uri you specified."
        "code"         | "45678"                   || "The request is missing a required parameter" | "whitelisted the redirect_uri you specified."
    }

    @Feature("OPENID_CONNECT")
    def "Request with url encoded state and nonce"() {
        given:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        flow.setState("testȺ田\uD83D\uDE0D&additional=1 %20")
        flow.setNonce("testȺ田\uD83D\uDE0D&additional=1 %20")
        paramsMap.put("state", flow.state)
        paramsMap.put("nonce", flow.nonce)
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
