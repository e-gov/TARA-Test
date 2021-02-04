package ee.ria.tara

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Ignore;
import spock.lang.Unroll
import com.nimbusds.jose.jwk.JWKSet

import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.startsWith
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat

class OpenIdConnectSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Unroll
    @Feature("OPENID_CONNECT")
    def "Metadata and token key ID matches"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        Response initOIDCServiceSession = Steps.createOIDCSessionWithParameters(flow, paramsMap)
        assertEquals("Correct HTTP status code is returned", 302, initOIDCServiceSession.statusCode())
        Response initLoginSession = Steps.createLoginSession(flow, initOIDCServiceSession)
        assertEquals("Correct HTTP status code is returned", 200, initLoginSession.statusCode())
        Response oidcServiceResponse = Steps.authWithMobileID(flow,"60001017727" , "69200366")
        String authorizationCode = Steps.getPermissionCode(flow, oidcServiceResponse)
        Response tokenResponse = Requests.getWebToken(flow, authorizationCode)
        assertEquals("Correct HTTP status code is returned", 200, tokenResponse.statusCode())
        Map<String, String> webToken = tokenResponse.body().jsonPath().getMap("\$.")
        String keyID = Steps.verifyTokenAndReturnSignedJwtObject(flow, webToken.get("id_token")).getHeader().getKeyID()
        assertThat(keyID, equalTo(flow.jwkSet.getKeys().get(0).getKeyID()))
    }

    @Unroll
    @Feature("OPENID_CONNECT")
    def "Request a token twice"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        Response initOIDCServiceSession = Steps.createOIDCSessionWithParameters(flow, paramsMap)
        assertEquals("Correct HTTP status code is returned", 302, initOIDCServiceSession.statusCode())
        Response initLoginSession = Steps.createLoginSession(flow, initOIDCServiceSession)
        assertEquals("Correct HTTP status code is returned", 200, initLoginSession.statusCode())
        Response oidcServiceResponse = Steps.authWithMobileID(flow,"60001017727" , "69200366")
        String authorizationCode = Steps.getPermissionCode(flow, oidcServiceResponse)
        // 1
        Response tokenResponse = Requests.getWebToken(flow, authorizationCode)
        // 2
        Response tokenResponse2 = Requests.getWebToken(flow, authorizationCode)
        assertEquals("Correct HTTP status code is returned", 400, tokenResponse2.statusCode())
        assertThat("Correct Content-Type is returned", tokenResponse2.getContentType(), startsWith("application/json"))
        assertEquals("Correct error message is returned", "invalid_grant", tokenResponse2.body().jsonPath().get("error"))
        assertEquals("Correct error hint is returned", "The authorization code has already been used.", tokenResponse2.body().jsonPath().get("error_hint"))
    }

    @Ignore // Etapp 4
    @Unroll
    @Feature("OPENID_CONNECT")
    def "Request with empty scope"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap.put("scope", "")
        Response response = Steps.createOIDCSessionWithParameters(flow, paramsMap)
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        assertEquals("Correct error value", " error text here", Utils.getParamValueFromResponseHeader(response, "error"))
    }

    @Unroll
    @Feature("OPENID_CONNECT")
    def "Request with invalid authorization code"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        Response initOIDCServiceSession = Steps.createOIDCSessionWithParameters(flow, paramsMap)
        assertEquals("Correct HTTP status code is returned", 302, initOIDCServiceSession.statusCode())
        Response initLoginSession = Steps.createLoginSession(flow, initOIDCServiceSession)
        assertEquals("Correct HTTP status code is returned", 200, initLoginSession.statusCode())
        Response oidcServiceResponse = Steps.authWithMobileID(flow,"60001017727" , "69200366")

        String authorizationCode = Steps.getPermissionCode(flow, oidcServiceResponse)
        Response response = Requests.getWebToken(flow, authorizationCode + "e")
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertThat("Correct Content-Type is returned", response.getContentType(), startsWith("application/json"))
        assertEquals("Correct error message is returned", "invalid_grant", response.body().jsonPath().get("error"))
    }

    @Unroll
    @Feature("OPENID_CONNECT")
    def "Request with missing parameter #paramName"() {
        expect:
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(formParamsMap, "grant_type", "code")
        def map2 = Utils.setParameter(formParamsMap, "code", "1234567")
        def map3 = Utils.setParameter(formParamsMap, "redirect_uri", flow.oidcClient.fullResponseUrl)
        formParamsMap.remove(paramName)
        Response response = Requests.getWebTokenResponseBody(flow, formParamsMap)
        assertEquals("Correct HTTP status code is returned", statusCode, response.statusCode())
        assertThat("Correct Content-Type is returned", response.getContentType(), startsWith("application/json"))
        assertEquals("Correct error message is returned", error, response.body().jsonPath().get("error"))
        assertThat("Correct error_hint value", response.body().jsonPath().get("error_hint"), startsWith(errorHint))

        where:
        paramName      || statusCode || error             || errorHint
        "code"         || 400        || "invalid_request" || "Make sure that the various parameters are correct"
        "grant_type"   || 400        || "invalid_request" || "Request parameter \"grant_type\"\" is missing"
        "redirect_uri" || 400        || "invalid_request" || "Make sure that the various parameters are correct"
    }


    @Unroll
    @Feature("OPENID_CONNECT")
    def "Request with invalid parameter value #paramName"() {
        expect:
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(formParamsMap, "grant_type", "code")
        def map2 = Utils.setParameter(formParamsMap, "code", "1234567")
        def map3 = Utils.setParameter(formParamsMap, "redirect_uri", flow.oidcClient.fullResponseUrl)
        def map4 = Utils.setParameter(formParamsMap, paramName, paramValue)
        Response response = Requests.getWebTokenResponseBody(flow, formParamsMap)
        assertEquals("Correct HTTP status code is returned", statusCode, response.statusCode())
        assertThat("Correct Content-Type is returned", response.getContentType(), startsWith("application/json"))
        assertEquals("Correct error message is returned", error, response.body().jsonPath().get("error"))
        assertThat("Correct error_hint value", response.body().jsonPath().get("error_hint"), startsWith(errorHint))

        where:
        paramName      | paramValue                || statusCode || error             || errorHint
        "redirect_uri" | "https://www.example.com" || 400        || "invalid_request" || "Make sure that the various parameters are correct"
        "grant_type"   | "token"                   || 400        || "invalid_request" || "Make sure that the various parameters are correct"
        "code"         | "45678"                   || 400        || "invalid_request" || "Make sure that the various parameters are correct"
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
        String authorizationCode = Steps.getPermissionCode(flow, oidcServiceResponse)
        Response tokenResponse = Requests.getWebToken(flow, authorizationCode)
        assertEquals("Correct HTTP status code is returned", 200, tokenResponse.statusCode())
        Map<String, String> webToken = tokenResponse.body().jsonPath().getMap("\$.")
        JWTClaimsSet claims =  SignedJWT.parse(webToken.get("id_token")).getJWTClaimsSet();
        assertThat(claims.getClaim("nonce"), equalTo(paramsMap.get("nonce")))
        // Should be fixed in id_token TARA2-182
        // assertThat(claims.getClaim("state"), equalTo(paramsMap.get("state")))
    }

}
