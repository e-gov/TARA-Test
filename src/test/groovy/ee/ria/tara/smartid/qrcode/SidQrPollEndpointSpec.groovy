package ee.ria.tara.smartid.qrcode


import ee.ria.tara.Requests
import ee.ria.tara.Steps
import ee.ria.tara.TaraSpecification
import ee.ria.tara.model.ErrorMessage
import ee.ria.tara.step.SidSteps
import ee.ria.tara.util.ErrorValidator
import io.restassured.filter.cookie.CookieFilter
import io.restassured.http.Method
import io.restassured.response.Response
import org.apache.http.HttpStatus

import static io.restassured.RestAssured.given
import static org.hamcrest.Matchers.equalTo

class SidQrPollEndpointSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
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
}
