package ee.ria.tara.smartid

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import ee.ria.tara.*
import ee.ria.tara.configuration.ConfigHolder
import ee.ria.tara.model.ErrorMessage
import ee.ria.tara.step.SidSteps
import ee.ria.tara.util.ErrorValidator
import io.restassured.filter.cookie.CookieFilter
import io.restassured.http.Method
import io.restassured.response.Response
import org.apache.http.HttpStatus
import spock.lang.Ignore

import static io.restassured.RestAssured.given
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*

class SmartIdAuthQrCodeSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    def "Authenticate with Smart-ID QR code flow"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Response sidAuthResponse = SidSteps.authenticateWithSidQrFlow(flow, "PNOEE-40404040009-MOCK-Q")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, sidAuthResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Incorrect audience", claims.audience[0], is(ClientStore.mockPublic.clientId))
        assertThat("Incorrect subject", claims.subject, is("EE40404040009"))
        assertThat("Incorrect given name", claims.getJSONObjectClaim("profile_attributes")["given_name"], is("OK"))
        assertThat("Incorrect family game", claims.getJSONObjectClaim("profile_attributes")["family_name"], is("TEST"))
        assertThat("Incorrect date of birth", claims.getJSONObjectClaim("profile_attributes")["date_of_birth"], is("1904-04-04"))
    }

    def "Initialize Smart-ID QR code authentication"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")

        when:
        Response response = SidSteps.initSidQrCodeAuthSession(flow)

        then:
        assertThat("Incorrect HTTP status code", response.statusCode, is(HttpStatus.SC_OK))
        assertThat("Incorrect Content-Type", response.contentType, is("text/html;charset=UTF-8"))
        String qrCodeDiv = response.htmlPath().getString("**.find { it -> it.@id == 'sidQrCode' }")
        assertThat("QR code element missing", qrCodeDiv, notNullValue())
    }

    def "Smart-ID QR code polling returns valid device link"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidQrCodeAuthSession(flow)

        when:
        String deviceLink = SidSteps.getSidQrCodeDeviceLink(flow)

        then:
        assertThat("Incorrect device link base", deviceLink, startsWith(ConfigHolder.testConf.sidDeviceLinkBase()))

        Map deviceLinkParams = Utils.parseQueryParams(deviceLink)
        assertThat("Incorrect device link type", deviceLinkParams.deviceLinkType, equalTo("QR"))
        assertThat("Missing elapsed seconds", deviceLinkParams.elapsedSeconds, notNullValue())
        assertThat("Missing session token", deviceLinkParams.sessionToken, notNullValue())
        assertThat("Incorrect session type", deviceLinkParams.sessionType, equalTo("auth"))
        assertThat("Incorrect version", deviceLinkParams.version, equalTo("1.0"))
        assertThat("Incorrect language", deviceLinkParams.lang, equalTo("est"))
        assertThat("Missing auth code", deviceLinkParams.authCode, notNullValue())
    }

    def "Initialize Smart-ID QR code authentication with invalid session cookie: #reason"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")

        when: "initialize Smart-ID authentication with invalid session cookie"
        Response response = given()
                .cookies(cookie)
                .params([_csrf: flow.csrf])
                .post(flow.loginService.sidQrCodeInitUrl)

        then:
        ErrorValidator.validate(response, ErrorMessage.INVALID_CSRF_TOKEN)

        where:
        cookie                        | reason
        [:]                           | "no cookie"
        ["__Host-SESSION": null]      | "empty cookie"
        ["__Host-SESSION": "1234567"] | "incorrect cookie value"
    }

    def "Initialize Smart-ID QR code authentication with invalid csrf token: #reason"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")

        when: "initialize Smart-ID authentication with invalid csrf token"
        Response response = given()
                .cookies(["__Host-SESSION": flow.sessionId])
                .params(params)
                .post(flow.loginService.sidQrCodeInitUrl)

        then:
        ErrorValidator.validate(response, ErrorMessage.INVALID_CSRF_TOKEN)

        where:
        params             | reason
        [:]                | "no csrf"
        [_csrf: null]      | "null"
        [_csrf: ""]        | "empty string"
        [_csrf: "1234567"] | "incorrect token value"
    }

    def "Initialize Smart-ID QR code authentication with invalid method: #requestType"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")

        when: "initialize Smart-ID authentication with invalid method"
        Response response = given()
                .cookies(["__Host-SESSION": flow.sessionId])
                .params([_csrf: flow.csrf])
                .request(requestType, flow.loginService.sidQrCodeInitUrl)
        then:
        ErrorValidator.validate(response, ErrorMessage.INTERNAL_ERROR)

        where:
        requestType   | _
        Method.GET    | _
        Method.PUT    | _
        Method.PATCH  | _
        Method.DELETE | _
    }

    @Ignore("Testing not supported by current device-link mock.")
    def "Initialize Smart-ID QR code authentication with scenario: #label et"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid", "et")
        SidSteps.initSidQrCodeAuthSession(flow)
        String deviceLink = SidSteps.getSidQrCodeDeviceLink(flow)
        SidSteps.initSidQrCodeMockAuth(flow, documentNumber, deviceLink)

        when:
        Response pollResponse = SidSteps.pollSidQrCodeSessionStatus(flow, 3000L)

        then:
        ErrorValidator.validate(pollResponse, HttpStatus.SC_BAD_REQUEST, errorMessage)
        pollResponse.then().body("reportable", is(false))

        where:
        documentNumber | label                              || errorMessage
        "TODO"         | "USER_REFUSED"                     || "Kasutaja katkestas autentimise<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses."
        "TODO"         | "USER_REFUSED_DISPLAYTEXTANDPIN"   || "Kasutaja katkestas<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses PIN koodi sisestamise."
        "TODO"         | "USER_REFUSED_CONFIRMATIONMESSAGE" || "Kasutaja katkestas autentimise<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses kinnitusekraanil."
    }

    @Ignore("Slow without dedicated test account (takes over 2min)")
    def "Initialize Smart-ID QR code authentication with scenario: TIMEOUT"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidQrCodeAuthSession(flow)

        when:
        Response pollResponse = SidSteps.pollSidQrCodeSessionStatus(flow, 10000L)

        then:
        ErrorMessage error = ErrorMessage.SID_SESSION_TIMED_OUT
        pollResponse.then()
                .statusCode(HttpStatus.SC_OK)
                .contentType("application/json;charset=UTF-8")
                .body(
                        "status", equalTo("FAILED"),
                        "error", equalTo("SID_SESSION_TIMEOUT"),
                        "message", equalTo(error.message)
                )
    }

    def "Poll Smart-ID QR code authentication session"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidQrCodeAuthSession(flow)

        when:
        Response response = Requests.pollSid(flow, flow.loginService.sidQrCodePollUrl)

        then:
        assertThat("Incorrect HTTP status code", response.statusCode, is(HttpStatus.SC_OK))
        assertThat("Incorrect Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Incorrect Mobile-ID status", response.jsonPath().getString("status"), is("PENDING"))
    }

    def "Poll Smart-ID QR code authentication with session complete"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidQrCodeAuthSession(flow)
        String deviceLink = SidSteps.getSidQrCodeDeviceLink(flow)
        SidSteps.initSidQrCodeMockAuth(flow, "PNOEE-40404040009-MOCK-Q", deviceLink)

        when:
        Response response = SidSteps.pollSidQrCodeSessionStatus(flow)

        then:
        assertThat("Incorrect HTTP status code", response.statusCode, is(HttpStatus.SC_OK))
        assertThat("Incorrect Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Incorrect Mobile-ID status", response.jsonPath().getString("status"), is("COMPLETED"))
    }

    def "Poll Smart-ID QR code authentication session with invalid session cookie: #reason"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidQrCodeAuthSession(flow)

        when: "request polling with invalid session cookie"
        Response response = given()
                .cookies(cookie)
                .get(flow.loginService.sidQrCodePollUrl)
        then:
        ErrorValidator.validate(response, ErrorMessage.SESSION_NOT_FOUND)

        where:
        cookie                        | reason
        [:]                           | "no cookie"
        ["__Host-SESSION": null]      | "empty cookie"
        ["__Host-SESSION": "1234567"] | "incorrect cookie value"
    }

    def "Poll Smart-ID QR code authentication in invalid session status"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")

        when: "request Smart-ID polling with invalid session status"
        Response pollResponse = Requests.pollSid(flow, flow.loginService.sidQrCodePollUrl)

        then:
        ErrorMessage error = ErrorMessage.SESSION_STATE_INVALID
        pollResponse.then()
                .statusCode(HttpStatus.SC_OK)
                .contentType("application/json;charset=UTF-8")
                .body(
                        "status", equalTo("FAILED"),
                        "error", equalTo(error.name()),
                        "message", equalTo(error.message)
                )
    }

    def "Poll Smart-ID QR code authentication with invalid method: #requestType"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidQrCodeAuthSession(flow)

        when: "request Smart-ID polling with invalid request type"
        Response response = given()
                .cookies("__Host-SESSION": flow.sessionId)
                .params([_csrf: flow.csrf])
                .request(requestType, flow.loginService.sidQrCodePollUrl)

        then:
        ErrorValidator.validate(response, ErrorMessage.INTERNAL_ERROR)

        where:
        requestType   | _
        Method.POST   | _
        Method.PUT    | _
        Method.PATCH  | _
        Method.DELETE | _
    }

    def "Cancel Smart-ID QR code authentication"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidQrCodeAuthSession(flow)

        when:
        Response response = Requests.postRequest(flow, flow.loginService.sidQrCodeCancelUrl)

        then:
        assertThat("Incorrect HTTP status code", response.statusCode, is(HttpStatus.SC_MOVED_TEMPORARILY))
        assertThat("Incorrect location header", response.header("location"), is(flow.loginService.initUrl + "?login_challenge=" + flow.loginChallenge + "&lang=et"))
        Steps.verifyResponseHeaders(response)
    }

    def "Cancel Smart-ID QR code authentication with invalid session cookie: #reason"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidQrCodeAuthSession(flow)

        when: "Cancel Smart-ID authentication with invalid session cookie"
        Response response = given()
                .cookies(cookie)
                .post(flow.loginService.sidQrCodeCancelUrl)

        then:
        ErrorValidator.validate(response, ErrorMessage.INVALID_CSRF_TOKEN)

        where:
        cookie                        | reason
        [:]                           | "no cookie"
        ["__Host-SESSION": null]      | "empty cookie"
        ["__Host-SESSION": "1234567"] | "incorrect cookie value"
    }

    def "Cancel Smart-ID QR code authentication with invalid csrf token: #reason"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidQrCodeAuthSession(flow)

        when: "Cancel Smart-ID authentication with invalid csrf token"
        Response response = given()
                .cookies(["__Host-SESSION": flow.sessionId])
                .params(params)
                .post(flow.loginService.sidQrCodeCancelUrl)

        then:
        ErrorValidator.validate(response, ErrorMessage.INVALID_CSRF_TOKEN)

        where:
        params             | reason
        [:]                | "no csrf"
        [_csrf: null]      | "null"
        [_csrf: ""]        | "empty string"
        [_csrf: "1234567"] | "incorrect token value"
    }

    def "Cancel Smart-ID QR code authentication with invalid method #requestType"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidQrCodeAuthSession(flow)

        when: "Cancel Smart-ID authentication with invalid method"
        Response response = given()
                .params([_csrf: flow.csrf])
                .cookies(["__Host-SESSION": flow.sessionId])
                .request(requestType, flow.loginService.sidQrCodeCancelUrl)

        then:
        ErrorValidator.validate(response, ErrorMessage.INTERNAL_ERROR)

        where:
        requestType   | _
        Method.GET    | _
        Method.PUT    | _
        Method.PATCH  | _
        Method.DELETE | _
    }
}
