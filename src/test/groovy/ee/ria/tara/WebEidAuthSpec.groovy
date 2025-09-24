package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import ee.ria.tara.model.ErrorMessage
import ee.ria.tara.util.ErrorValidator
import io.qameta.allure.Feature
import io.qameta.allure.Issue
import io.qameta.allure.Step
import io.restassured.filter.cookie.CookieFilter
import io.restassured.http.Method
import io.restassured.response.Response
import org.json.JSONObject

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.notNullValue

class WebEidAuthSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    def "Authenticate with ID-Card. TEST of ESTEID2018 chain certificate"() {
        given:
        Steps.startAuthenticationInTara(flow)

        when:
        Response tokenResponse = Steps.authenticateWithWebEid(flow)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience[0], equalTo(ClientStore.mockPublic.clientId))
        assertThat("Correct subject", claims.subject, equalTo("EE38001085718"))
        assertThat("Correct authentication method", claims.getClaim("amr"), equalTo(["idcard"]))
    }

    def "Init Web eID authentication"() {
        given:
        Steps.startAuthenticationInTara(flow)

        when:
        Response initWebEid = Requests.postRequest(flow, flow.loginService.fullWebEidInitUrl)

        then:
        assertThat("Correct HTTP status code", initWebEid.statusCode, is(200))
        assertThat("Correct Content-Type", initWebEid.contentType, is("application/json;charset=UTF-8"))
        assertThat("Challenge nonce for Web eID", initWebEid.jsonPath().get("nonce"), is(notNullValue()))
    }

    def "Init Web eID authentication twice"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Requests.postRequest(flow, flow.loginService.fullWebEidInitUrl)

        when:
        Response initWebEid = Requests.postRequest(flow, flow.loginService.fullWebEidInitUrl)

        then:
        assertThat("Correct HTTP status code", initWebEid.statusCode, is(200))
        assertThat("Correct Content-Type", initWebEid.contentType, is("application/json;charset=UTF-8"))
        assertThat("Challenge nonce for Web eID", initWebEid.jsonPath().get("nonce"), is(notNullValue()))
    }


    def "Init Web eID authentication with incorrect SESSION cookie"() {
        given:
        Steps.startAuthenticationInTara(flow)
        flow.setSessionId("00000000-0000-0000-0000-00000000")

        when:
        Response initWebEid = Requests.postRequest(flow, flow.loginService.fullWebEidInitUrl)

        then:
        ErrorValidator.validate(initWebEid, ErrorMessage.INVALID_CSRF_TOKEN)
    }

    def "Init Web eID authentication with incorrect _csrf code"() {
        given:
        Steps.startAuthenticationInTara(flow)
        flow.setCsrf("00000000-0000-0000-0000-00000000")

        when:
        Response initWebEid = Requests.postRequest(flow, flow.loginService.fullWebEidInitUrl)

        then:
        ErrorValidator.validate(initWebEid, ErrorMessage.INVALID_CSRF_TOKEN)
    }

    @Issue("AUT-630")
    def "Init Web eID authentication with unsupported request type: #requestType"() {
        given:
        Steps.startAuthenticationInTara(flow)

        when:
        Response initWebEid = Requests.requestWithType(flow, requestType, flow.loginService.fullWebEidInitUrl)

        then:
        ErrorValidator.validate(initWebEid, ErrorMessage.INTERNAL_ERROR)

        where:
        requestType   | _
        Method.GET    | _
        Method.PUT    | _
        Method.PATCH  | _
        Method.DELETE | _
    }

    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Init Web eID authentication, verify headers"() {
        given:
        Steps.startAuthenticationInTara(flow)

        when:
        Response initWebEid = Requests.postRequest(flow, flow.loginService.fullWebEidInitUrl)

        then:
        Steps.verifyResponseHeaders(initWebEid)
    }

    def "Submit login request for Web eID authentication with valid authentication token"() {
        given:
        JSONObject authToken = authenticationFlowToWebEidParams(flow)

        when:
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then:
        assertThat("Correct HTTP status code", loginWebEid.statusCode, is(200))
        assertThat("Correct Content-Type", loginWebEid.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct status", loginWebEid.jsonPath().getString("status"), is("COMPLETED"))
    }

    def "Submit login request for Web eID authentication with same valid authentication token twice"() {
        given:
        JSONObject authToken = authenticationFlowToWebEidParams(flow)
        Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        when:
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then:
        ErrorValidator.validate(loginWebEid, ErrorMessage.SESSION_STATE_INVALID)
    }

    def "Submit login request for Web eID authentication with invalid SESSION cookie"() {
        given:
        JSONObject authToken = authenticationFlowToWebEidParams(flow)
        flow.setSessionId("00000000-0000-0000-0000-00000000")

        when:
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then:
        ErrorValidator.validate(loginWebEid, ErrorMessage.INVALID_CSRF_TOKEN)
    }

    def "Submit login request for Web eID authentication with invalid _csrf code"() {
        given:
        JSONObject authToken = authenticationFlowToWebEidParams(flow)
        flow.setCsrf("00000000-0000-0000-0000-00000000")

        when:
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then:
        ErrorValidator.validate(loginWebEid, ErrorMessage.INVALID_CSRF_TOKEN)
    }

    def "Submit login request for Web eID authentication without init request"() {
        given:
        Steps.startAuthenticationInTara(flow)
        String signAuthValue = Utils.signAuthenticationValue(flow, flow.loginService.baseUrl, "V2ViRWlkQXV0aEluaXRMb2dpbk5vbmNlVsOkbGphbcO1ZWxkdWQ=")
        JSONObject authToken = Utils.getWebEidAuthTokenParameters(flow, signAuthValue)

        when:
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then:
        ErrorValidator.validate(loginWebEid, ErrorMessage.INVALID_REQUEST)
    }

    def "Submit login request for Web eID authentication with empty authentication token"() {
        given:
        Steps.startAuthenticationInTara(flow)
        JSONObject authToken = ["authToken": [:]]

        when:
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then:
        ErrorValidator.validate(loginWebEid, ErrorMessage.INVALID_REQUEST)
    }

    def "Submit login request for Web eID authentication with invalid authentication token: #reason"() {
        given:
        JSONObject authToken = authenticationFlowToWebEidParams(flow)
        authToken.getJSONObject("authToken").put(key, value)

        when:
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then:
        ErrorValidator.validate(loginWebEid, message)

        where:
        reason                        | key                     | value         | message
        "incorrect format value"      | "format"                | "web-eid:666" | ErrorMessage.INVALID_REQUEST
        "empty format value"          | "format"                | ""            | ErrorMessage.INVALID_REQUEST
        "incorrect certificate value" | "unverifiedCertificate" | "certificate" | ErrorMessage.INVALID_REQUEST
        "empty certificate value"     | "unverifiedCertificate" | ""            | ErrorMessage.INVALID_REQUEST
        "incorrect signature value"   | "signature"             | "signature"   | ErrorMessage.INTERNAL_ERROR // TODO: why is this different?
        "empty signature value"       | "signature"             | ""            | ErrorMessage.INVALID_REQUEST
        "incorrect algorithm value"   | "algorithm"             | "RSA384"      | ErrorMessage.INVALID_REQUEST
        "empty algorithm value"       | "algorithm"             | ""            | ErrorMessage.INVALID_REQUEST
    }

    def "Submit login request for Web eID authentication with invalid authentication token: authToken missing #key"() {
        given:
        JSONObject authToken = authenticationFlowToWebEidParams(flow)
        authToken.getJSONObject("authToken").remove(key)

        when:
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then:
        ErrorValidator.validate(loginWebEid, ErrorMessage.INVALID_REQUEST)
        loginWebEid.then().body("reportable", is(false))

        where:
        key                     | _
        "format"                | _
        "unverifiedCertificate" | _
        "signature"             | _
        "algorithm"             | _
    }

    @Feature("REJECT_EXPIRED_CERTS")
    def "Submit login request for Web eID authentication with expired certificate"() {
        given:
        JSONObject authToken = authenticationFlowToWebEidParams(flow)
        authToken.getJSONObject("authToken").put("unverifiedCertificate", Utils.getCertificateAsString("src/test/resources/expired-cert_base64.txt"))

        when:
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then:
        ErrorValidator.validate(loginWebEid, ErrorMessage.IDC_CERT_EXPIRED)
        loginWebEid.then().body("reportable", is(false))
    }

    @Feature("REJECT_REVOKED_CERTS")
    def "Submit login request for Web eID authentication with revoked certificate"() {
        given:
        JSONObject authToken = authenticationFlowToWebEidParams(flow, "src/test/resources/revoked_auth_EC.p12")

        when:
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then:
        ErrorValidator.validate(loginWebEid, ErrorMessage.IDC_REVOKED)
        loginWebEid.then().body("reportable", is(false))
    }

    @Feature("REJECT_UNKNOWN_CERTS")
    def "Submit login request for Web eID authentication with unknown certificate"() {
        given:
        JSONObject authToken = authenticationFlowToWebEidParams(flow, "src/test/resources/unknown_auth_EC.p12")

        when:
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then:
        ErrorValidator.validate(loginWebEid, ErrorMessage.IDC_REVOKED)
        loginWebEid.then().body("reportable", is(false))
    }

    def "Submit login request for Web eID authentication with unsupported request type: #requestType"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Requests.postRequest(flow, flow.loginService.fullWebEidInitUrl)

        when:
        Response loginWebEid = Requests.requestWithType(flow, requestType, flow.loginService.fullWebEidLoginUrl)

        then:
        ErrorValidator.validate(loginWebEid, ErrorMessage.INTERNAL_ERROR)

        where:
        requestType   | _
        Method.GET    | _
        Method.PUT    | _
        Method.PATCH  | _
        Method.DELETE | _
    }

    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Submit login request for Web eID authentication, verify headers"() {
        given:
        JSONObject authToken = authenticationFlowToWebEidParams(flow)

        when:
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then:
        Steps.verifyResponseHeaders(loginWebEid)
    }

    @Step("Authentication flow up to Web eID authentication token generation")
    private static authenticationFlowToWebEidParams(Flow flow, String keyStore = "src/test/resources/joeorg_auth_EC.p12") {
        Steps.startAuthenticationInTara(flow)
        Response initWebEid = Requests.postRequest(flow, flow.loginService.fullWebEidInitUrl)
        String signAuthValue = Utils.signAuthenticationValue(flow, flow.loginService.baseUrl, initWebEid.jsonPath().get("nonce"), keyStore)
        JSONObject authToken = Utils.getWebEidAuthTokenParameters(flow, signAuthValue)
        return authToken
    }
}
