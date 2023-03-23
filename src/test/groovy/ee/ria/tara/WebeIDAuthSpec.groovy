package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.json.JSONObject
import spock.lang.Unroll

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

    @Unroll
    def "Authenticate with ID-Card. TEST of ESTEID2018 chain certificate"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response tokenResponse = Steps.authenticateWithWebeID(flow)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()

        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientPublic.clientId))
        assertThat(claims.getSubject(), equalTo("EE38001085718"))
        assertThat(claims.getClaim("amr"), equalTo(["idcard"]))
    }

    @Unroll
    def "Init Web eID authentication"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response initWebEid = Requests.postRequestWithSessionId(flow, flow.loginService.fullWebEidInitUrl)

        assertThat("Correct HTTP status code is returned", initWebEid.statusCode(), is(200))
        assertThat("Correct Content-Type is returned", initWebEid.getHeader("Content-Type"), is("application/json;charset=UTF-8"))
        assertThat("Challenge nonce for Web eID is returned", initWebEid.jsonPath().get("nonce"), is(notNullValue()))
    }

    @Unroll
    def "Init Web eID authentication twice"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Requests.postRequestWithSessionId(flow, flow.loginService.fullWebEidInitUrl)
        Response initWebEid = Requests.postRequestWithSessionId(flow, flow.loginService.fullWebEidInitUrl)

        assertThat("Correct HTTP status code is returned", initWebEid.statusCode(), is(200))
        assertThat("Correct Content-Type is returned", initWebEid.getHeader("Content-Type"), is("application/json;charset=UTF-8"))
        assertThat("Challenge nonce for Web eID is returned", initWebEid.jsonPath().get("nonce"), is(notNullValue()))
    }


    @Unroll
    def "Init Web eID authentication with incorrect SESSION cookie"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        flow.setSessionId("00000000-0000-0000-0000-00000000")
        Response initWebEid = Requests.postRequestWithSessionId(flow, flow.loginService.fullWebEidInitUrl)

        assertThat("Correct HTTP status code is returned", initWebEid.statusCode(), is(403))
        assertThat("Correct status is returned", initWebEid.jsonPath().get("error").toString(), is("Forbidden"))
        assertThat("Correct message is returned", initWebEid.jsonPath().get("message").toString(), is("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
    }

    @Unroll
    def "Init Web eID authentication with incorrect _csrf code"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        flow.setCsrf("00000000-0000-0000-0000-00000000")
        Response initWebEid = Requests.postRequestWithSessionId(flow, flow.loginService.fullWebEidInitUrl)

        assertThat("Correct HTTP status code is returned", initWebEid.statusCode(), is(403))
        assertThat("Correct status is returned", initWebEid.jsonPath().get("error").toString(), is("Forbidden"))
        assertThat("Correct message is returned", initWebEid.jsonPath().get("message").toString(), is("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
    }

    //TODO: AUT-630
    @Unroll
    def "Init Web eID authentication with unsupported request type: #requestType"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response initWebEid = Requests.requestWithSessionId(flow, requestType, flow.loginService.fullWebEidInitUrl)

        assertThat("Correct HTTP status code is returned", initWebEid.statusCode(), is(500))
        assertThat("Correct status is returned", initWebEid.jsonPath().get("error").toString(), is("Internal Server Error"))
        assertThat("Correct message is returned", initWebEid.jsonPath().get("message").toString(), is("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))

        where:
        _ | requestType
        _ | "get"
        _ | "put"
        _ | "patch"
        _ | "delete"
    }

    @Unroll
    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Init Web eID authentication, verify headers"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response initWebEid = Requests.postRequestWithSessionId(flow, flow.loginService.fullWebEidInitUrl)
        Steps.verifyResponseHeaders(initWebEid)
    }

    @Unroll
    def "Submit login request for Web eID authentication with valid authentication token"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response initWebEid = Requests.postRequestWithSessionId(flow, flow.loginService.fullWebEidInitUrl)

        String signAuthValue = Utils.signAuthenticationValue(flow, flow.loginService.baseUrl, initWebEid.jsonPath().get("nonce"))
        JSONObject authToken = Utils.getWebEidAuthTokenParameters(flow, signAuthValue)

        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        assertThat("Correct HTTP status code is returned", loginWebEid.statusCode(), is(200))
        assertThat("Correct Content-Type is returned", loginWebEid.getHeader("Content-Type"), is("application/json;charset=UTF-8"))
        assertThat("Correct status is returned", loginWebEid.jsonPath().get("status").toString(), is("COMPLETED"))
    }

    @Unroll
    def "Submit login request for Web eID authentication with same valid authentication token twice"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response initWebEid = Requests.postRequestWithSessionId(flow, flow.loginService.fullWebEidInitUrl)

        String signAuthValue = Utils.signAuthenticationValue(flow, flow.loginService.baseUrl, initWebEid.jsonPath().get("nonce"))
        JSONObject authToken = Utils.getWebEidAuthTokenParameters(flow, signAuthValue)

        Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)


        assertThat("Correct HTTP status code is returned", loginWebEid.statusCode(), is(400))
        assertThat("Correct status is returned", loginWebEid.jsonPath().get("error").toString(), is("Bad Request"))
        assertThat("Correct message is returned", loginWebEid.jsonPath().get("message").toString(), is("Ebakorrektne päring. Vale seansi staatus."))
    }

    @Unroll
    def "Submit login request for Web eID authentication with invalid SESSION cookie"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response initWebEid = Requests.postRequestWithSessionId(flow, flow.loginService.fullWebEidInitUrl)

        String signAuthValue = Utils.signAuthenticationValue(flow, flow.loginService.baseUrl, initWebEid.jsonPath().get("nonce"))
        JSONObject authToken = Utils.getWebEidAuthTokenParameters(flow, signAuthValue)

        flow.setSessionId("00000000-0000-0000-0000-00000000")
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        assertThat("Correct HTTP status code is returned", loginWebEid.statusCode(), is(403))
        assertThat("Correct status is returned", loginWebEid.jsonPath().get("error").toString(), is("Forbidden"))
        assertThat("Correct message is returned", loginWebEid.jsonPath().get("message").toString(), is("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
    }

    @Unroll
    def "Submit login request for Web eID authentication with invalid _csrf code"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response initWebEid = Requests.postRequestWithSessionId(flow, flow.loginService.fullWebEidInitUrl)

        String signAuthValue = Utils.signAuthenticationValue(flow, flow.loginService.baseUrl, initWebEid.jsonPath().get("nonce"))
        JSONObject authToken = Utils.getWebEidAuthTokenParameters(flow, signAuthValue)

        flow.setCsrf("00000000-0000-0000-0000-00000000")
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        assertThat("Correct HTTP status code is returned", loginWebEid.statusCode(), is(403))
        assertThat("Correct status is returned", loginWebEid.jsonPath().get("error").toString(), is("Forbidden"))
        assertThat("Correct message is returned", loginWebEid.jsonPath().get("message").toString(), is("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
    }

    @Unroll
    def "Submit login request for Web eID authentication without init request"() {
        expect:
        Steps.startAuthenticationInTara(flow)

        String signAuthValue = Utils.signAuthenticationValue(flow, flow.loginService.baseUrl, "V2ViRWlkQXV0aEluaXRMb2dpbk5vbmNlVsOkbGphbcO1ZWxkdWQ=")
        JSONObject authToken = Utils.getWebEidAuthTokenParameters(flow, signAuthValue)

        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        assertThat("Correct HTTP status code is returned", loginWebEid.statusCode(), is(400))
        assertThat("Correct status is returned", loginWebEid.jsonPath().get("error").toString(), is("Bad Request"))
        assertThat("Correct message is returned", loginWebEid.jsonPath().get("message").toString(), is("Ebakorrektne päring."))
    }

    @Unroll
    def "Submit login request for Web eID authentication with empty authentication token"() {
        expect:
        Steps.startAuthenticationInTara(flow)

        JSONObject authToken = new JSONObject()
        JSONObject empty = new JSONObject()
        authToken.put("authToken", empty)

        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        assertThat("Correct HTTP status code is returned", loginWebEid.statusCode(), is(400))
        assertThat("Correct status is returned", loginWebEid.jsonPath().get("error").toString(), is("Bad Request"))
        assertThat("Correct message is returned", loginWebEid.jsonPath().get("message").toString(), is("Ebakorrektne päring."))
    }

    @Unroll
    def "Submit login request for Web eID authentication with invalid authentication token: #reason"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response initWebEid = Requests.postRequestWithSessionId(flow, flow.loginService.fullWebEidInitUrl)

        String signAuthValue = Utils.signAuthenticationValue(flow, flow.loginService.baseUrl, initWebEid.jsonPath().get("nonce"))
        JSONObject authToken = Utils.getWebEidAuthTokenParameters(flow, signAuthValue)
        authToken.getJSONObject("authToken").put(key, value)

        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        assertThat("Correct HTTP status code is returned", loginWebEid.statusCode(), is(statusCode))
        assertThat("Correct status is returned", loginWebEid.jsonPath().get("error").toString(), is(error))
        assertThat("Correct message is returned", loginWebEid.jsonPath().get("message").toString(), is(message))

        where:
        reason                        | key                     | value         | statusCode | error                   | message
        "incorrect format value"      | "format"                | "web-eid:666" | 400        | "Bad Request"           | "Ebakorrektne päring."
        "empty format value"          | "format"                | ""            | 400        | "Bad Request"           | "Ebakorrektne päring."
        "incorrect certificate value" | "unverifiedCertificate" | "certificate" | 400        | "Bad Request"           | "Ebakorrektne päring."
        "empty certificate value"     | "unverifiedCertificate" | ""            | 400        | "Bad Request"           | "Ebakorrektne päring."
        "incorrect signature value"   | "signature"             | "signature"   | 500        | "Internal Server Error" | "Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."
        "empty signature value"       | "signature"             | ""            | 400        | "Bad Request"           | "Ebakorrektne päring."
        "incorrect algorithm value"   | "algorithm"             | "RSA384"      | 400        | "Bad Request"           | "Ebakorrektne päring."
        "empty algorithm value"       | "algorithm"             | ""            | 400        | "Bad Request"           | "Ebakorrektne päring."
    }

    @Unroll
    def "Submit login request for Web eID authentication with invalid authentication token: authToken missing #key"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response initWebEid = Requests.postRequestWithSessionId(flow, flow.loginService.fullWebEidInitUrl)

        String signAuthValue = Utils.signAuthenticationValue(flow, flow.loginService.baseUrl, initWebEid.jsonPath().get("nonce"))
        JSONObject authToken = Utils.getWebEidAuthTokenParameters(flow, signAuthValue)

        authToken.getJSONObject("authToken").remove(key)

        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        assertThat("Correct HTTP status code is returned", loginWebEid.statusCode(), is(statusCode))
        assertThat("Correct error is returned", loginWebEid.jsonPath().get("error").toString(), is(error))
        assertThat("Correct message is returned", loginWebEid.jsonPath().get("message").toString(), is(message))
        assertThat("Error is reportable", loginWebEid.jsonPath().get("reportable") as Boolean, is(false))

        where:
        key                     | statusCode | error         | message
        "format"                | 400        | "Bad Request" | "Ebakorrektne päring."
        "unverifiedCertificate" | 400        | "Bad Request" | "Ebakorrektne päring."
        "signature"             | 400        | "Bad Request" | "Ebakorrektne päring."
        "algorithm"             | 400        | "Bad Request" | "Ebakorrektne päring."
    }

    @Feature("REJECT_EXPIRED_CERTS")
    @Unroll
    def "Submit login request for Web eID authentication with expired certificate"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response initWebEid = Requests.postRequestWithSessionId(flow, flow.loginService.fullWebEidInitUrl)

        String signAuthValue = Utils.signAuthenticationValue(flow, flow.loginService.baseUrl, initWebEid.jsonPath().get("nonce"))
        JSONObject authToken = Utils.getWebEidAuthTokenParameters(flow, signAuthValue)
        authToken.getJSONObject("authToken").put("unverifiedCertificate", Utils.getCertificateAsString("src/test/resources/expired-cert_base64.txt"))

        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        assertThat("Correct HTTP status code is returned", loginWebEid.statusCode(), is(400))
        assertThat("Correct error is returned", loginWebEid.jsonPath().get("error").toString(), is("Bad Request"))
        assertThat("Correct message is returned", loginWebEid.jsonPath().get("message").toString(), is("ID-kaardi sertifikaadid ei kehti."))
        assertThat("Error not reportable", loginWebEid.jsonPath().get("reportable") as Boolean, is(false))
    }

    @Feature("REJECT_REVOKED_CERTS")
    @Unroll
    def "Submit login request for Web eID authentication with revoked certificate"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response initWebEid = Requests.postRequestWithSessionId(flow, flow.loginService.fullWebEidInitUrl)

        String signAuthValue = Utils.signAuthenticationValue(flow, flow.loginService.baseUrl, initWebEid.jsonPath().get("nonce"), "src/test/resources/revoked_auth_EC.p12")
        JSONObject authToken = Utils.getWebEidAuthTokenParameters(flow, signAuthValue)

        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        assertThat("Correct HTTP status code is returned", loginWebEid.statusCode(), is(400))
        assertThat("Correct error is returned", loginWebEid.jsonPath().get("error").toString(), is("Bad Request"))
        assertThat("Correct message is returned", loginWebEid.jsonPath().get("message").toString(), is("ID-kaardi sertifikaadid on peatatud või tühistatud. Palun pöörduge Politsei- ja Piirivalveameti teenindusse."))
        assertThat("Error not reportable", loginWebEid.jsonPath().get("reportable") as Boolean, is(false))

    }

    @Feature("REJECT_UNKNOWN_CERTS")
    @Unroll
    def "Submit login request for Web eID authentication with unknown certificate"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response initWebEid = Requests.postRequestWithSessionId(flow, flow.loginService.fullWebEidInitUrl)

        String signAuthValue = Utils.signAuthenticationValue(flow, flow.loginService.baseUrl, initWebEid.jsonPath().get("nonce"), "src/test/resources/unknown_auth_EC.p12")
        JSONObject authToken = Utils.getWebEidAuthTokenParameters(flow, signAuthValue)

        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        assertThat("Correct HTTP status code is returned", loginWebEid.statusCode(), is(400))
        assertThat("Correct error is returned", loginWebEid.jsonPath().get("error").toString(), is("Bad Request"))
        assertThat("Correct message is returned", loginWebEid.jsonPath().get("message").toString(), is("ID-kaardi sertifikaadid on peatatud või tühistatud. Palun pöörduge Politsei- ja Piirivalveameti teenindusse."))
        assertThat("Error not reportable", loginWebEid.jsonPath().get("reportable") as Boolean, is(false))

    }

    @Unroll
    def "Submit login request for Web eID authentication with unsupported request type: #requestType"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Requests.postRequestWithSessionId(flow, flow.loginService.fullWebEidInitUrl)

        Response loginWebEid = Requests.requestWithSessionId(flow, requestType, flow.loginService.fullWebEidLoginUrl)

        assertThat("Correct HTTP status code is returned", loginWebEid.statusCode(), is(500))
        assertThat("Correct status is returned", loginWebEid.jsonPath().get("error").toString(), is("Internal Server Error"))
        assertThat("Correct message is returned", loginWebEid.jsonPath().get("message").toString(), is("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))

        where:
        _ | requestType
        _ | "get"
        _ | "put"
        _ | "patch"
        _ | "delete"
    }

    @Unroll
    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Submit login request for Web eID authentication, verify headers"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response initWebEid = Requests.postRequestWithSessionId(flow, flow.loginService.fullWebEidInitUrl)
        String signAuthValue = Utils.signAuthenticationValue(flow, flow.loginService.baseUrl, initWebEid.jsonPath().get("nonce"))
        JSONObject authToken = Utils.getWebEidAuthTokenParameters(flow, signAuthValue)
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)
        Steps.verifyResponseHeaders(loginWebEid)
    }
}
