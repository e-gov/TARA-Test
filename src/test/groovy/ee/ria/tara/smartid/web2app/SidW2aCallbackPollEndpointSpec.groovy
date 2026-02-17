package ee.ria.tara.smartid.web2app


import ee.ria.tara.Steps
import ee.ria.tara.TaraSpecification
import ee.ria.tara.model.ErrorMessage
import ee.ria.tara.step.SidSteps
import ee.ria.tara.util.ErrorValidator
import io.restassured.filter.cookie.CookieFilter
import io.restassured.http.Method
import io.restassured.response.Response

import static io.restassured.RestAssured.given

class SidW2aCallbackPollEndpointSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    def "Poll Smart-ID web2app authentication session after callback with invalid session cookie: #reason"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidWeb2AppAuthSession(flow)

        when: "Poll Smart-ID authentication with invalid session cookie"
        Response callbackPoll = given()
                .cookies(cookie)
                .params(SidSteps.sidWeb2AppCallbackPollDefaultParams(flow))
                .get(flow.loginService.sidWeb2AppCallbackPollUrl)

        then:
        ErrorValidator.validate(callbackPoll, ErrorMessage.SESSION_NOT_FOUND)

        where:
        cookie                        | reason
        [:]                           | "no cookie"
        ["__Host-SESSION": null]      | "empty cookie"
        ["__Host-SESSION": "1234567"] | "incorrect cookie value"
    }

    def "Poll Smart-ID web2app authentication session after callback with invalid method #requestType"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidWeb2AppAuthSession(flow)

        when: "Poll Smart-ID authentication with invalid method"
        Response callbackPoll = given()
                .cookies(["__Host-SESSION": flow.sessionId])
                .params(SidSteps.sidWeb2AppCallbackPollDefaultParams(flow))
                .request(requestType, flow.loginService.sidWeb2AppCallbackPollUrl)

        then:
        ErrorValidator.validate(callbackPoll, ErrorMessage.INTERNAL_ERROR)

        where:
        requestType   | _
        Method.POST   | _
        Method.PUT    | _
        Method.PATCH  | _
        Method.DELETE | _
    }
}
