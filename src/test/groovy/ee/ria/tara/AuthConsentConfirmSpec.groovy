package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.commons.lang3.RandomStringUtils

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*

class AuthConsentConfirmSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Feature("USER_CONSENT_ENDPOINT")
    @Feature("UI_CONSENT_VIEW")
    def "Consent with authentication results"() {
        given:
        Steps.startAuthenticationInTaraWithSpecificProxyService(flow)

        when:
        Response response = Steps.authenticateWithMid(flow, "60001017716", "69100366")

        then: "Correct status code and info in HTML"
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        List<String> identityFields = response.htmlPath().getList("**.findAll {th -> th.@colspan == \'1\'}.b")
        List<String> buttons = response.htmlPath().getList("**.findAll { it.@method == \'POST\'}.button")
        assertThat("Correct buttons", buttons, hasItems("Nõustun", "Keeldun"))
        assertThat("Correct fields", identityFields, hasItems("Isikukood:", "Perenimi:", "Eesnimi:", "Sünniaeg:"))
        assertThat("Correct ID code", response.htmlPath().getString("**.find { it.@id == 'natural-person-id-code'}"), is("60001017716"))
        assertThat("Correct surname", response.htmlPath().getString("**.find { it.@id == 'natural-person-surname'}"), is("TESTNUMBER"))
        assertThat("Correct given name", response.htmlPath().getString("**.find { it.@id == 'natural-person-given-name'}"), is("ONE"))
        assertThat("Correct date of birth", response.htmlPath().getString("**.find { it.@id == 'natural-person-date-of-birth'}"), is("01.01.2000"))
    }

    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent with authentication results. Invalid session ID"() {
        given:
        Steps.startAuthenticationInTaraWithSpecificProxyService(flow)
        Requests.startMidAuthentication(flow, "60001017716", "69100366")
        Steps.pollMidResponse(flow)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        flow.setSessionId("1234567")

        when:
        Response response = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString("message"), is(MESSAGE_SESSION_NOT_FOUND))
    }

    //TODO: AUT-630
    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent with authentication results. Invalid method post"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Requests.startMidAuthentication(flow, "60001017716", "69100366")
        Steps.pollMidResponse(flow)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        String location = oidcServiceResponse.header("location")

        when:
        Response response = Requests.postRequestWithSessionId(flow, location)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_INTERNAL_ERROR))
    }

    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent with authentication results. Missing session ID"() {
        given:
        Steps.startAuthenticationInTaraWithSpecificProxyService(flow)
        Requests.startMidAuthentication(flow, "60001017716", "69100366")
        Steps.pollMidResponse(flow)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)

        when:
        Response response = Steps.followRedirect(flow, oidcServiceResponse)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_SESSION_NOT_FOUND))
    }

    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent with authentication results. #label"() {
        given:
        Steps.startAuthenticationInTaraWithSpecificProxyService(flow)
        Requests.startMidAuthentication(flow, "60001017716", "69100366")
        Steps.pollMidResponse(flow)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        Steps.getOAuthCookies(flow, acceptResponse)

        Map cookiesMap = ["SESSION": flow.sessionId]
        Map paramsMap = [:]
        Utils.setParameter(paramsMap, paramName, paramValue)
        Map additionalParamsMap = [:]
        Utils.setParameter(additionalParamsMap, additionalParamName, additionalParamValue)

        when:
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullConsentUrl, cookiesMap, paramsMap, additionalParamsMap)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString("message"), startsWith(errorMessage))

        where:
        paramName           | paramValue                               | additionalParamName | additionalParamValue | label                                                      || errorMessage
        _                   | _                                        | _                   | _                    | "Missing parameter consent_challenge"                      || "Required request parameter 'consent_challenge' for method parameter type String is not present"
        "consent_challenge" | _                                        | _                   | _                    | "Empty parameter consent_challenge value"                  || "authConsent.consentChallenge: only characters and numbers allowed"
        "consent_challenge" | RandomStringUtils.random(51, true, true) | _                   | _                    | "Too long consent_challenge"                               || "authConsent.consentChallenge: size must be between 0 and 50"
        "consent_challenge" | "342%26abz"                              | _                   | _                    | "Invalid symbols in the consent_challenge parameter value" || "authConsent.consentChallenge: only characters and numbers allowed"
        "consent_challenge" | "ABCD1234"                               | "consent_challenge" | "1234abc"            | "Multiple consent_challenge parameters"                    || MESSAGE_DUPLICATE_PARAMETERS
    }

    @Feature("USER_CONSENT_ENDPOINT")
    @Feature("USER_CONSENT_POST_ACCEPT")
    def "Consent with invalid consent challenge value"() {
        given:
        Steps.startAuthenticationInTaraWithSpecificProxyService(flow)
        Requests.startMidAuthentication(flow, "60001017716", "69100366")
        Steps.pollMidResponse(flow)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        Steps.getOAuthCookies(flow, acceptResponse)

        Map cookiesMap = ["SESSION": flow.sessionId]
        Map paramsMap = ["consent_challenge": RandomStringUtils.random(50, true, true)]
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullConsentUrl, cookiesMap, paramsMap, [:])
        flow.setCsrf(response.htmlPath().get("**.find {it.@name == '_csrf'}.@value"))

        when:
        Response consentConfirmResponse = Steps.submitConsent(flow, true)

        then:
        assertThat("Correct HTTP status code", consentConfirmResponse.statusCode, is(500))
        assertThat("Correct Content-Type", consentConfirmResponse.contentType, is("application/json;charset=UTF-8"))
        assertThat(consentConfirmResponse.jsonPath().get("message").toString(), is(MESSAGE_INTERNAL_ERROR))
        assertThat(consentConfirmResponse.jsonPath().get("path").toString(), is("/auth/consent/confirm"))
    }

    @Feature("USER_CONSENT_CONFIRM_ENDPOINT")
    @Feature("USER_CONSENT_POST_ACCEPT")
    def "Confirm consent"() {
        given:
        Steps.startAuthenticationInTaraWithSpecificProxyService(flow)
        Steps.authenticateWithMid(flow, "60001017727", "69200366")

        when:
        Response consentConfirmResponse = Steps.submitConsent(flow, true)

        then:
        assertThat("Correct HTTP status code", consentConfirmResponse.statusCode, is(302))
        assertThat("Correct location header", consentConfirmResponse.header("location"), startsWith(flow.oidcService.baseUrl + "/oidc/authorize"))
        assertThat("Correct state", Utils.getParamValueFromResponseHeader(consentConfirmResponse, "state"), is(flow.state))
        assertThat("Session cookie is invalidated", consentConfirmResponse.cookie("SESSION"), is(emptyString()))
    }

    @Feature("USER_CONSENT_CONFIRM_ENDPOINT")
    def "Confirm consent with authentication results. Invalid session ID"() {
        given:
        Steps.startAuthenticationInTaraWithSpecificProxyService(flow)
        Steps.authenticateWithMid(flow,"60001017727" , "69200366")
        flow.setSessionId("1234567")

        when:
        Response response = Steps.submitConsent(flow, true)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(403))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_FORBIDDEN))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_FORBIDDEN_REQUEST))
    }

    @Feature("USER_CONSENT_CONFIRM_ENDPOINT")
    def "Confirm consent with authentication results. Invalid method get"() {
        given:
        Map cookiesMap = ["SESSION": "1234567"]
        Map paramsMap = ["consent_given": true]

        when:
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullConsentConfirmUrl, cookiesMap, paramsMap, [:])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().get("message").toString(), is(MESSAGE_INTERNAL_ERROR))
    }

    @Feature("USER_CONSENT_CONFIRM_ENDPOINT")
    def "Confirm consent with authentication results. Missing session ID"() {
        given:
        Steps.startAuthenticationInTaraWithSpecificProxyService(flow)
        Steps.authenticateWithMid(flow, "60001017727", "69200366")

        Map paramsMap = [
                "consent_given": true,
                "_csrf": flow.csrf]

        when:
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullConsentConfirmUrl, [:], paramsMap, [:])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(403))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", response.jsonPath().get("error").toString(), is(ERROR_FORBIDDEN))
        assertThat("Correct message", response.jsonPath().get("message").toString(), is(MESSAGE_FORBIDDEN_REQUEST))
    }

    @Feature("USER_CONSENT_CONFIRM_ENDPOINT")
    def "Confirm consent with authentication results. #label"() {
        given:
        Steps.startAuthenticationInTaraWithSpecificProxyService(flow)
        Steps.authenticateWithMid(flow, "60001017727", "69200366")

        Map cookiesMap = ["SESSION": flow.sessionId]
        Map paramsMap = ["_csrf": flow.csrf]
        Utils.setParameter(paramsMap, paramName, paramValue)
        Map additionalParamsMap = [:]
        Utils.setParameter(additionalParamsMap, additionalParamName, additionalParamValue)

        when:
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullConsentConfirmUrl, cookiesMap, paramsMap, additionalParamsMap)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString("message"), is(errorMessage))

        where:
        paramName       | paramValue | additionalParamName | additionalParamValue | label                                 || errorMessage
        _               | _          | _                   | _                    | "Missing parameter consent_given"     || "Required request parameter 'consent_given' for method parameter type String is not present"
        "consent_given" | _          | _                   | _                    | "Empty parameter consent_given value" || "authConsentConfirm.consentGiven: supported values are: 'true', 'false'"
        "consent_given" | "abc123"   | _                   | _                    | "Invalid consent_given value"         || "authConsentConfirm.consentGiven: supported values are: 'true', 'false'"
        "consent_given" | "false"    | "consent_given"     | "true"               | "Multiple consent_given parameters"   || MESSAGE_DUPLICATE_PARAMETERS
    }

    @Feature("USER_CONSENT_POST_REJECT")
    def "Reject consent with authentication results"() {
        given:
        Steps.startAuthenticationInTaraWithSpecificProxyService(flow)
        Steps.authenticateWithMid(flow, "60001017716", "69100366")
        Response consentRejectResult = Steps.submitConsent(flow, false)

        when:
        Response response = Steps.followRedirectWithCookies(flow, consentRejectResult, flow.oidcClientPublic.cookies)

        then:
        assertThat("Correct error", Utils.getParamValueFromResponseHeader(response, "error"), is(REJECT_ERROR_CODE))
        assertThat("Correct error description", Utils.getParamValueFromResponseHeader(response, "error_description"), is("Consent not given. User canceled the authentication process."))
        assertThat("Correct state", Utils.getParamValueFromResponseHeader(response, "state"), is(flow.state))
    }
}
