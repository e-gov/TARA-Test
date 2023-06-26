package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.qameta.allure.Step
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.json.JSONObject

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.notNullValue

class WebeIDAuthSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    def "Authenticate with ID-Card. TEST of ESTEID2018 chain certificate"() {
        given:
        Steps.startAuthenticationInTara(flow)

        when:
        Response tokenResponse = Steps.authenticateWithWebeID(flow)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience[0], equalTo(flow.oidcClientPublic.clientId))
        assertThat("Correct subject", claims.subject, equalTo("EE38001085718"))
        assertThat("Correct authentication method", claims.getClaim("amr"), equalTo(["idcard"]))
    }

    def "Init Web eID authentication"() {
        given:
        Steps.startAuthenticationInTara(flow)

        when:
        Response initWebEid = Requests.postRequestWithParams(flow, flow.loginService.fullWebEidInitUrl)

        then:
        assertThat("Correct HTTP status code", initWebEid.statusCode, is(200))
        assertThat("Correct Content-Type", initWebEid.contentType, is("application/json;charset=UTF-8"))
        assertThat("Challenge nonce for Web eID", initWebEid.jsonPath().get("nonce"), is(notNullValue()))
    }

    def "Init Web eID authentication twice"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Requests.postRequestWithParams(flow, flow.loginService.fullWebEidInitUrl)

        when:
        Response initWebEid = Requests.postRequestWithParams(flow, flow.loginService.fullWebEidInitUrl)

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
        Response initWebEid = Requests.postRequestWithParams(flow, flow.loginService.fullWebEidInitUrl)

        then:
        assertThat("Correct HTTP status code", initWebEid.statusCode, is(403))
        assertThat("Correct status", initWebEid.jsonPath().getString("error"), is(ERROR_FORBIDDEN))
        assertThat("Correct message", initWebEid.jsonPath().getString("message"), is(MESSAGE_FORBIDDEN_REQUEST))
    }

    def "Init Web eID authentication with incorrect _csrf code"() {
        given:
        Steps.startAuthenticationInTara(flow)
        flow.setCsrf("00000000-0000-0000-0000-00000000")

        when:
        Response initWebEid = Requests.postRequestWithParams(flow, flow.loginService.fullWebEidInitUrl)

        then:
        assertThat("Correct HTTP status code", initWebEid.statusCode, is(403))
        assertThat("Correct status", initWebEid.jsonPath().getString("error"), is(ERROR_FORBIDDEN))
        assertThat("Correct message", initWebEid.jsonPath().getString("message"), is(MESSAGE_FORBIDDEN_REQUEST))
    }

    //TODO: AUT-630
    def "Init Web eID authentication with unsupported request type: #requestType"() {
        given:
        Steps.startAuthenticationInTara(flow)

        when:
        Response initWebEid = Requests.requestWithType(flow, requestType, flow.loginService.fullWebEidInitUrl)

        then:
        assertThat("Correct HTTP status code", initWebEid.statusCode, is(500))
        assertThat("Correct status", initWebEid.jsonPath().getString("error"), is(ERROR_INTERNAL))
        assertThat("Correct message", initWebEid.jsonPath().getString("message"), is(MESSAGE_INTERNAL_ERROR))

        where:
        _ | requestType
        _ | "get"
        _ | "put"
        _ | "patch"
        _ | "delete"
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
        Response initWebEid = Requests.postRequestWithParams(flow, flow.loginService.fullWebEidInitUrl)

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
        assertThat("Correct HTTP status code", loginWebEid.statusCode, is(400))
        assertThat("Correct status", loginWebEid.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", loginWebEid.jsonPath().getString("message"), is("Ebakorrektne päring. Vale seansi staatus."))
    }

    def "Submit login request for Web eID authentication with invalid SESSION cookie"() {
        given:
        JSONObject authToken = authenticationFlowToWebEidParams(flow)
        flow.setSessionId("00000000-0000-0000-0000-00000000")

        when:
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then:
        assertThat("Correct HTTP status code", loginWebEid.statusCode, is(403))
        assertThat("Correct status", loginWebEid.jsonPath().getString("error"), is(ERROR_FORBIDDEN))
        assertThat("Correct message", loginWebEid.jsonPath().getString("message"), is(MESSAGE_FORBIDDEN_REQUEST))
    }

    def "Submit login request for Web eID authentication with invalid _csrf code"() {
        given:
        JSONObject authToken = authenticationFlowToWebEidParams(flow)
        flow.setCsrf("00000000-0000-0000-0000-00000000")

        when:
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then:
        assertThat("Correct HTTP status code", loginWebEid.statusCode, is(403))
        assertThat("Correct status", loginWebEid.jsonPath().getString("error"), is(ERROR_FORBIDDEN))
        assertThat("Correct message", loginWebEid.jsonPath().getString("message"), is(MESSAGE_FORBIDDEN_REQUEST))
    }

    def "Submit login request for Web eID authentication without init request"() {
        given:
        Steps.startAuthenticationInTara(flow)
        String signAuthValue = Utils.signAuthenticationValue(flow, flow.loginService.baseUrl, "V2ViRWlkQXV0aEluaXRMb2dpbk5vbmNlVsOkbGphbcO1ZWxkdWQ=")
        JSONObject authToken = Utils.getWebEidAuthTokenParameters(flow, signAuthValue)

        when:
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then:
        assertThat("Correct HTTP status code", loginWebEid.statusCode, is(400))
        assertThat("Correct status", loginWebEid.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", loginWebEid.jsonPath().getString("message"), is(MESSAGE_INCORRECT_REQUEST))
    }

    def "Submit login request for Web eID authentication with empty authentication token"() {
        given:
        Steps.startAuthenticationInTara(flow)
        JSONObject authToken = ["authToken": [:]]

        when:
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then:
        assertThat("Correct HTTP status code", loginWebEid.statusCode, is(400))
        assertThat("Correct status", loginWebEid.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", loginWebEid.jsonPath().getString("message"), is(MESSAGE_INCORRECT_REQUEST))
    }

    def "Submit login request for Web eID authentication with invalid authentication token: #reason"() {
        given:
        JSONObject authToken = authenticationFlowToWebEidParams(flow)
        authToken.getJSONObject("authToken").put(key, value)

        when:
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then:
        assertThat("Correct HTTP status code", loginWebEid.statusCode, is(statusCode))
        assertThat("Correct status", loginWebEid.jsonPath().getString("error"), is(error))
        assertThat("Correct message", loginWebEid.jsonPath().getString("message"), is(message))

        where:
        reason                        | key                     | value         | statusCode | error             | message
        "incorrect format value"      | "format"                | "web-eid:666" | 400        | ERROR_BAD_REQUEST | MESSAGE_INCORRECT_REQUEST
        "empty format value"          | "format"                | ""            | 400        | ERROR_BAD_REQUEST | MESSAGE_INCORRECT_REQUEST
        "incorrect certificate value" | "unverifiedCertificate" | "certificate" | 400        | ERROR_BAD_REQUEST | MESSAGE_INCORRECT_REQUEST
        "empty certificate value"     | "unverifiedCertificate" | ""            | 400        | ERROR_BAD_REQUEST | MESSAGE_INCORRECT_REQUEST
        "incorrect signature value"   | "signature"             | "signature"   | 500        | ERROR_INTERNAL    | MESSAGE_INTERNAL_ERROR
        "empty signature value"       | "signature"             | ""            | 400        | ERROR_BAD_REQUEST | MESSAGE_INCORRECT_REQUEST
        "incorrect algorithm value"   | "algorithm"             | "RSA384"      | 400        | ERROR_BAD_REQUEST | MESSAGE_INCORRECT_REQUEST
        "empty algorithm value"       | "algorithm"             | ""            | 400        | ERROR_BAD_REQUEST | MESSAGE_INCORRECT_REQUEST
    }

    def "Submit login request for Web eID authentication with invalid authentication token: authToken missing #key"() {
        given:
        JSONObject authToken = authenticationFlowToWebEidParams(flow)
        authToken.getJSONObject("authToken").remove(key)

        when:
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then:
        assertThat("Correct HTTP status code", loginWebEid.statusCode, is(400))
        assertThat("Correct error", loginWebEid.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", loginWebEid.jsonPath().getString("message"), is(MESSAGE_INCORRECT_REQUEST))
        assertThat("Error is reportable", loginWebEid.jsonPath().get("reportable") as Boolean, is(false))

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
        assertThat("Correct HTTP status code", loginWebEid.statusCode, is(400))
        assertThat("Correct error", loginWebEid.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", loginWebEid.jsonPath().getString("message"), is("ID-kaardi sertifikaadid ei kehti."))
        assertThat("Error not reportable", loginWebEid.jsonPath().getBoolean("reportable"), is(false))
    }

    @Feature("REJECT_REVOKED_CERTS")
    def "Submit login request for Web eID authentication with revoked certificate"() {
        given:
        JSONObject authToken = authenticationFlowToWebEidParams(flow, "src/test/resources/revoked_auth_EC.p12")

        when:
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then:
        assertThat("Correct HTTP status code", loginWebEid.statusCode, is(400))
        assertThat("Correct error", loginWebEid.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", loginWebEid.jsonPath().getString("message"), is("ID-kaardi sertifikaadid on peatatud või tühistatud. Palun pöörduge Politsei- ja Piirivalveameti teenindusse."))
        assertThat("Error not reportable", loginWebEid.jsonPath().getBoolean("reportable"), is(false))

    }

    @Feature("REJECT_UNKNOWN_CERTS")
    def "Submit login request for Web eID authentication with unknown certificate"() {
        given:
        JSONObject authToken = authenticationFlowToWebEidParams(flow, "src/test/resources/unknown_auth_EC.p12")

        when:
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then:
        assertThat("Correct HTTP status code", loginWebEid.statusCode, is(400))
        assertThat("Correct error", loginWebEid.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", loginWebEid.jsonPath().getString("message"), is("ID-kaardi sertifikaadid on peatatud või tühistatud. Palun pöörduge Politsei- ja Piirivalveameti teenindusse."))
        assertThat("Error not reportable", loginWebEid.jsonPath().getBoolean("reportable"), is(false))

    }

    def "Submit login request for Web eID authentication with unsupported request type: #requestType"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Requests.postRequestWithParams(flow, flow.loginService.fullWebEidInitUrl)

        when:
        Response loginWebEid = Requests.requestWithType(flow, requestType, flow.loginService.fullWebEidLoginUrl)

        then:
        assertThat("Correct HTTP status code", loginWebEid.statusCode, is(500))
        assertThat("Correct status", loginWebEid.jsonPath().getString("error"), is(ERROR_INTERNAL))
        assertThat("Correct message", loginWebEid.jsonPath().getString("message"), is(MESSAGE_INTERNAL_ERROR))

        where:
        _ | requestType
        _ | "get"
        _ | "put"
        _ | "patch"
        _ | "delete"
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
        Response initWebEid = Requests.postRequestWithParams(flow, flow.loginService.fullWebEidInitUrl)
        String signAuthValue = Utils.signAuthenticationValue(flow, flow.loginService.baseUrl, initWebEid.jsonPath().get("nonce"), keyStore)
        JSONObject authToken = Utils.getWebEidAuthTokenParameters(flow, signAuthValue)
        return authToken
    }
}
