package ee.ria.tara.smartid.web2app


import ee.ria.tara.Requests
import ee.ria.tara.Steps
import ee.ria.tara.TaraSpecification
import ee.ria.tara.Utils
import ee.ria.tara.model.ErrorMessage
import ee.ria.tara.step.SidSteps
import ee.ria.tara.util.ErrorValidator
import io.restassured.filter.cookie.CookieFilter
import io.restassured.http.Method
import io.restassured.response.Response

import static io.restassured.RestAssured.given

class SidW2aPollEndpointSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    def "Poll Smart-ID web2app authentication session with invalid session cookie: #reason"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidWeb2AppAuthSession(flow)

        when: "request polling with invalid session cookie"
        Response response = given()
                .cookies(cookie)
                .queryParams([sessionToken: "testToken"])
                .params([_csrf: flow.csrf])
                .get(flow.loginService.sidWeb2AppPollUrl)
        then:
        ErrorValidator.validate(response, ErrorMessage.SESSION_NOT_FOUND)

        where:
        cookie                        | reason
        [:]                           | "no cookie"
        ["__Host-SESSION": null]      | "empty cookie"
        ["__Host-SESSION": "1234567"] | "incorrect cookie value"
    }

    def "Poll Smart-ID web2app authentication with #label: sessionToken"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidWeb2AppAuthSession(flow)

        when:
        Response pollResponse = Requests.pollSid(flow, flow.loginService.sidWeb2AppPollUrl, params)

        then:
        ErrorValidator.validate(pollResponse, errorMessage, "sessionToken")

        where:
        label             | params                            || errorMessage
        "missing param"   | [:]                               || ErrorMessage.MISSING_PARAMETERS
        "invalid param"   | [sessionToken: "invalidToken"]    || ErrorMessage.SESSION_STATE_INVALID
        "duplicate param" | [sessionToken: ["test", "test2"]] || ErrorMessage.DUPLICATE_PARAMETERS
    }

    def "Poll Smart-ID web2app authentication with old sessionToken"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Response authInitResponse = SidSteps.initSidWeb2AppAuthSession(flow)
        String deviceLink = authInitResponse.jsonPath().getString("deviceLink")
        Map queryParams = [sessionToken: Utils.parseQueryParams(deviceLink).sessionToken]

        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidWeb2AppAuthSession(flow)

        when:
        Response pollResponse = Requests.getRequestWithParams(flow, flow.loginService.sidWeb2AppPollUrl, queryParams)

        then:
        ErrorValidator.validate(pollResponse, ErrorMessage.SESSION_STATE_INVALID)
    }

    def "Poll Smart-ID web2app authentication with invalid method: #requestType"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidWeb2AppAuthSession(flow)

        when: "request Smart-ID polling with invalid request type"
        Response response = given()
                .cookies("__Host-SESSION": flow.sessionId)
                .params([_csrf: flow.csrf])
                .request(requestType, flow.loginService.sidWeb2AppPollUrl)

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
