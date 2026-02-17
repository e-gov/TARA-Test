package ee.ria.tara.smartid.web2app


import ee.ria.tara.Steps
import ee.ria.tara.TaraSpecification
import ee.ria.tara.model.ErrorMessage
import ee.ria.tara.step.SidSteps
import ee.ria.tara.util.ErrorValidator
import io.restassured.filter.cookie.CookieFilter
import io.restassured.http.Method
import io.restassured.response.Response
import spock.lang.Ignore

import static io.restassured.RestAssured.given

class SidW2aCallbackEndpointSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Ignore("AUT-2600")
    def "Smart-ID web2app authentication callback with invalid session cookie: #reason"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidWeb2AppAuthSession(flow)

        when: "Smart-ID callback with invalid session cookie"
        Response response = given()
                .cookies(cookie)
                .get(flow.loginService.sidWeb2AppCallbackUrl)

        then:
        ErrorValidator.validate(response, ErrorMessage.SESSION_NOT_FOUND)

        where:
        cookie                        | reason
        [:]                           | "no cookie"
        ["__Host-SESSION": null]      | "empty cookie"
        ["__Host-SESSION": "1234567"] | "incorrect cookie value"
    }

    def "Smart-ID web2app authentication callback with invalid method #requestType"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidWeb2AppAuthSession(flow)

        when: "Smart-ID callback with invalid method"
        Response response = given()
                .cookies(["__Host-SESSION": flow.sessionId])
                .params([_csrf: flow.csrf])
                .request(requestType, flow.loginService.sidWeb2AppCallbackUrl)

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
