package ee.ria.tara.smartid.qrcode


import ee.ria.tara.Steps
import ee.ria.tara.TaraSpecification
import ee.ria.tara.model.ErrorMessage
import ee.ria.tara.step.SidSteps
import ee.ria.tara.util.ErrorValidator
import io.restassured.filter.cookie.CookieFilter
import io.restassured.http.Method
import io.restassured.response.Response

import static io.restassured.RestAssured.given

class SidQrCancelEndpointSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
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
