package ee.ria.tara

import io.qameta.allure.Feature
import io.qameta.allure.Step
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.commons.lang3.RandomStringUtils

import static io.restassured.RestAssured.given
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.hasItems
import static org.hamcrest.Matchers.startsWith
import static org.hamcrest.Matchers.emptyString

class AuthConsentConfirmSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Feature("USER_CONSENT_ENDPOINT")
    @Feature("UI_CONSENT_VIEW")
    def "Consent confirmation HTML holds correct information"() {
        given:
        Steps.startAuthenticationInTaraWithSpecificProxyService(flow)

        when:
        Response response = Steps.authenticateWithMid(flow, "60001017716", "69100366")

        then: "Correct status code and info in HTML"
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        List<String> identityFields = response.htmlPath().getList("**.findAll { div -> div.@class == 'personal-info-label'}")
        List<String> buttons = response.htmlPath().getList("**.findAll { it.@method == \'POST\'}.button")
        assertThat("Correct buttons", buttons, hasItems("Nõustu", "Keeldu"))
        assertThat("Correct fields", identityFields, hasItems("Isikukood", "Perenimi", "Eesnimi", "Sünniaeg"))
        assertThat("Correct ID code", response.htmlPath().getString("**.find { it.@id == 'natural-person-id-code'}"), is("EE60001017716"))
        assertThat("Correct surname", response.htmlPath().getString("**.find { it.@id == 'natural-person-surname'}"), is("TESTNUMBER"))
        assertThat("Correct given name", response.htmlPath().getString("**.find { it.@id == 'natural-person-given-name'}"), is("ONE"))
        assertThat("Correct date of birth", response.htmlPath().getString("**.find { it.@id == 'natural-person-date-of-birth'}"), is("01.01.2000"))
    }

    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent request with incorrect session cookie should fail: #reason"() {
        given:
        Response loginVerifier = authenticateToLoginVerifier(flow)

        when: "Consent request with #reason"
        Response response = given()
                .relaxedHTTPSValidation()
                .cookies(cookie)
                .get(loginVerifier.getHeader("location"))

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString("message"), is(MESSAGE_SESSION_NOT_FOUND))

        where:
        cookie                        | reason
        [:]                           | "no cookie"
        ["__Host-SESSION": null]      | "empty cookie"
        ["__Host-SESSION": "1234567"] | "incorrect cookie value"
    }

    //TODO: AUT-630
    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent request with invalid request type should fail: #requestType"() {
        given:
        Response loginVerifier = authenticateToLoginVerifier(flow)

        when: "Consent request with invalid request type: #requestType"
        Response response = given()
                .relaxedHTTPSValidation()
                .cookie("__Host-SESSION", flow.sessionId)
                .params("_csrf", flow.csrf)
                .request(requestType, loginVerifier.header("location"))

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_INTERNAL_ERROR))

        where:
        requestType | _
        "POST"      | _
        "PUT"       | _
        "PATCH"     | _
        "DELETE"    | _
    }

    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent with authentication results. #label"() {
        given:
        authenticateToLoginVerifier(flow)

        when: "Consent request with invalid consent_challenge"
        Response response = Requests.getRequestWithParams(flow, flow.loginService.fullConsentUrl, paramsMap)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString("message"), startsWith(errorMessage))

        where:
        paramsMap                                                     | label                                                      || errorMessage
        [:]                                                           | "Missing parameter consent_challenge"                      || "Required request parameter 'consent_challenge' for method parameter type String is not present"
        [consent_challenge: ""]                                       | "Empty parameter consent_challenge value"                  || "authConsent.consentChallenge: only characters and numbers allowed"
        [consent_challenge: RandomStringUtils.random(51, true, true)] | "Too long consent_challenge"                               || "authConsent.consentChallenge: size must be between 0 and 50"
        [consent_challenge: "342%26abz"]                              | "Invalid symbols in the consent_challenge parameter value" || "authConsent.consentChallenge: only characters and numbers allowed"
        [consent_challenge: ["ABCD1234", "1234abc"]]                  | "Multiple consent_challenge parameters"                    || MESSAGE_DUPLICATE_PARAMETERS
    }

    @Feature("USER_CONSENT_ENDPOINT")
    @Feature("USER_CONSENT_POST_ACCEPT")
    def "Request consent confirmation with invalid consent challenge value"() {
        given:
        authenticateToLoginVerifier(flow)
        Requests.getRequestWithParams(flow, flow.loginService.fullConsentUrl, ["consent_challenge": RandomStringUtils.random(50, true, true)])

        when:
        Response response = Steps.submitConsent(flow, true)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_INTERNAL_ERROR))
        assertThat("Correct path", response.jsonPath().getString("path"), is("/auth/consent/confirm"))
    }

    @Feature("USER_CONSENT_CONFIRM_ENDPOINT")
    @Feature("USER_CONSENT_POST_ACCEPT")
    def "Consent confirmation is successful"() {
        given:
        authenticateToConsent(flow)

        when:
        Response consentConfirmResponse = Steps.submitConsent(flow, true)

        then:
        assertThat("Correct HTTP status code", consentConfirmResponse.statusCode, is(302))
        assertThat("Correct location header", consentConfirmResponse.header("location"), startsWith(flow.oidcService.baseUrl + "/oidc/authorize"))
        assertThat("Correct state", Utils.getParamValueFromResponseHeader(consentConfirmResponse, "state"), is(flow.state))
        assertThat("Session cookie is invalidated", consentConfirmResponse.cookie("__Host-SESSION"), is(emptyString()))
    }

    @Feature("USER_CONSENT_CONFIRM_ENDPOINT")
    def "Consent confirmation request with invalid request type: #requestType"() {
        given:
        authenticateToConsent(flow)

        when: "Consent confirmation request with invalid request type"
        Response response = given()
                .relaxedHTTPSValidation()
                .filter(flow.cookieFilter)
                .params([_csrf        : flow.csrf,
                         consent_given: true])
                .request(requestType, flow.loginService.fullConsentConfirmUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_INTERNAL_ERROR))

        where:
        requestType | _
        "GET"       | _
        "PUT"       | _
        "PATCH"     | _
        "DELETE"    | _
    }

    @Feature("USER_CONSENT_CONFIRM_ENDPOINT")
    def "Confirm consent with incorrect session cookie should fail: #reason"() {
        given:
        authenticateToConsent(flow)

        when: "Submit consent confirmation with incorrect session cookie"
        Response response = given()
                .relaxedHTTPSValidation()
                .cookies(cookie)
                .formParams(["consent_given": true,
                             "_csrf"        : flow.csrf])
                .post(flow.loginService.fullConsentConfirmUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(403))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_FORBIDDEN))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_FORBIDDEN_REQUEST))

        where:
        cookie                        | reason
        [:]                           | "no cookie"
        ["__Host-SESSION": null]      | "empty cookie"
        ["__Host-SESSION": "1234567"] | "incorrect cookie value"
    }

    @Feature("USER_CONSENT_CONFIRM_ENDPOINT")
    def "Confirm consent with incorrect consent_given parameter should fail. #label"() {
        given:
        authenticateToConsent(flow)

        Map paramsMap = ["_csrf": flow.csrf]
        paramsMap << paramName

        when: "Submit consent"
        Response response = Requests.postRequestWithParams(flow, flow.loginService.fullConsentConfirmUrl, paramsMap)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString("message"), is(errorMessage))

        where:
        paramName                            | label                                 || errorMessage
        [:]                                  | "Missing parameter consent_given"     || "Required request parameter 'consent_given' for method parameter type String is not present"
        ["consent_given": ""]                | "Empty parameter consent_given value" || "authConsentConfirm.consentGiven: supported values are: 'true', 'false'"
        ["consent_given": "abc123"]          | "Invalid consent_given value"         || "authConsentConfirm.consentGiven: supported values are: 'true', 'false'"
        ["consent_given": ["false", "true"]] | "Multiple consent_given parameters"   || MESSAGE_DUPLICATE_PARAMETERS
    }

    @Feature("USER_CONSENT_POST_REJECT")
    def "Reject consent should return correct error in URL"() {
        given:
        authenticateToConsent(flow)
        Response consentRejectResult = Steps.submitConsent(flow, false)

        when:
        Response response = Steps.followRedirectWithCookies(flow, consentRejectResult, flow.oidcClientPublic.cookies)

        then:
        assertThat("Correct error", Utils.getParamValueFromResponseHeader(response, "error"), is(REJECT_ERROR_CODE))
        assertThat("Correct error description", Utils.getParamValueFromResponseHeader(response, "error_description"), is("Consent not given. User canceled the authentication process."))
        assertThat("Correct state", Utils.getParamValueFromResponseHeader(response, "state"), is(flow.state))
    }

    @Step("Authentication flow up to OIDC login verifier request")
    private static authenticateToLoginVerifier(Flow flow) {
        Steps.startAuthenticationInTaraWithSpecificProxyService(flow)
        Requests.startMidAuthentication(flow, "60001017869", "68000769")
        Steps.pollMidResponse(flow)
        Response acceptResponse = Requests.postRequest(flow, flow.loginService.fullAuthAcceptUrl)
        Response loginVerifier = Steps.loginVerifier(flow, acceptResponse)
        return loginVerifier
    }

    @Step("Authentication flow up to consent request")
    private static authenticateToConsent(Flow flow) {
        Steps.startAuthenticationInTaraWithSpecificProxyService(flow)
        Steps.authenticateWithMid(flow, "60001017869", "68000769")
    }

}
