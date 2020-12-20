package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.commons.lang.RandomStringUtils
import org.hamcrest.Matchers
import spock.lang.Ignore
import spock.lang.Unroll

import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.startsWith
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat

class AuthConsentConfirmSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent with authentication results"() {
        expect:
        Response initResponse = Steps.authWithMobileID(flow)
        Response response = Steps.followRedirectWithSessionId(flow, initResponse)
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        assertThat(response.getHeader("location"), Matchers.startsWith(flow.oidcService.fullAuthenticationRequestUrl))
    }

    @Unroll
    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent with authentication results. Invalid session ID"() {
        expect:
        Response initResponse = Steps.authWithMobileID(flow)
        flow.setSessionId("1234567")
        Response response = Steps.followRedirectWithSessionId(flow, initResponse)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }

    @Ignore // TARA2-76
    @Unroll
    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent with authentication results. Invalid method post"() {
        expect:
        Response initResponse = Steps.authWithMobileID(flow)
        String location = initResponse.getHeader("location")
        Response response = Requests.followRedirectWithSessionId(flow, REQUEST_TYPE_POST, location)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), equalTo("Request method 'POST' not supported"))
    }

    @Ignore // TARA2-76
    @Unroll
    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent with authentication results. Missing session ID"() {
        expect:
        Response initResponse = Steps.authWithMobileID(flow)
        Response response = Steps.followRedirect(flow, initResponse)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }

    @Unroll
    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent with authentication results. #label"() {
        expect:
        Response initResponse = Steps.authWithMobileID(flow)
        String location = initResponse.getHeader("location")
        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(cookiesMap, "SESSION", flow.sessionId)
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(paramsMap, paramName, paramValue)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(additionalParamsMap, additionalParamName, additionalParamValue)
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullConsentUrl, cookiesMap, paramsMap, additionalParamsMap)

        assertEquals("Correct HTTP status code is returned", statusCode, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), startsWith(errorMessage))

        where:
        paramName           | paramValue                               | additionalParamName | additionalParamValue | label                                                      || statusCode || errorMessage
        _                   | _                                        | _                   | _                    | "Missing parameter consent_challenge"                      || 400        || "Required String parameter 'consent_challenge' is not present"
        "consent_challenge" | _                                        | _                   | _                    | "Empty parameter consent_challenge value"                  || 400        || "authConsent.consentChallenge: only characters and numbers allowed"
        "consent_challenge" | RandomStringUtils.random(51, true, true) | _                   | _                    | "Too long consent_challenge"                               || 400        || "authConsent.consentChallenge: size must be between 0 and 50"
        "consent_challenge" | RandomStringUtils.random(50, true, true) | _                   | _                    | "Correct consent_challenge length"                         || 400        || "a'la consent with ID not found"
        "consent_challenge" | "342%26abz"                              | _                   | _                    | "Invalid symbols in the consent_challenge parameter value" || 400        || "authConsent.consentChallenge: only characters and numbers allowed"
        "consent_challenge" | "ABCD1234"                               | "consent_challenge" | "1234abc"            | "Multiple consent_challenge parameters"                    || 400        || "Multiple request parameters with the same name not allowed"
    }

    @Unroll
    @Feature("USER_CONSENT_CONFIRM_ENDPOINT")
    def "Confirm consent with authentication results. Invalid session ID"() {
        expect:
        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(cookiesMap, "SESSION", "1234567")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(paramsMap, "consent_given", true)
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullConsenConfirmUrl, cookiesMap, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }

    @Ignore // TARA2-76
    @Unroll
    @Feature("USER_CONSENT_CONFIRM_ENDPOINT")
    def "Confirm consent with authentication results. Invalid method get"() {
        expect:
        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(cookiesMap, "SESSION", "1234567")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(paramsMap, "consent_given", true)
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullConsenConfirmUrl, cookiesMap, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertEquals("Correct error message is returned", "Request method 'GET' not supported", response.body().jsonPath().get("message"))
    }

    @Unroll
    @Feature("USER_CONSENT_CONFIRM_ENDPOINT")
    def "Confirm consent with authentication results. Missing session ID"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(paramsMap, "consent_given", true)
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullConsenConfirmUrl, Collections.emptyMap(), paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }

    @Unroll
    @Feature("USER_CONSENT_CONFIRM_ENDPOINT")
    def "Confirm consent with authentication results. #label"() {
        expect:
        Response initResponse = Steps.authWithMobileID(flow)
        Response consentResponse = Steps.followRedirectWithSessionId(flow, initResponse)
        assertEquals("Correct HTTP status code is returned", 302, consentResponse.statusCode())
        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(cookiesMap, "SESSION", flow.sessionId)
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(paramsMap, paramName, paramValue)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(additionalParamsMap, additionalParamName, additionalParamValue)
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullConsenConfirmUrl, cookiesMap, paramsMap, additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", statusCode, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertEquals("Correct error message is returned", errorMessage, response.body().jsonPath().get("message"))

        where:
        paramName       | paramValue | additionalParamName | additionalParamValue | label                                 || statusCode || errorMessage
        _               | _          | _                   | _                    | "Missing parameter consent_given"     || 400        || "Required String parameter 'consent_given' is not present"
        "consent_given" | _          | _                   | _                    | "Empty parameter consent_given value" || 400        || "authConsentConfirm.consentGiven: supported values are: 'true', 'false'"
        "consent_given" | "abc123"   | _                   | _                    | "Invalid consent_given value"         || 400        || "authConsentConfirm.consentGiven: supported values are: 'true', 'false'"
        "consent_given" | "false"    | _                   | _                    | "Session does not exists"             || 400        || "Ebakorrektne päring. Vale sessiooni staatus."
        "consent_given" | "false"    | "consent_given"     | "true"               | "Multiple consent_given parameters"   || 400        || "Multiple request parameters with the same name not allowed"
    }

}
