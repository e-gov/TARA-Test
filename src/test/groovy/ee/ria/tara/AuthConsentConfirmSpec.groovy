package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.commons.lang.RandomStringUtils
import org.hamcrest.Matchers
import spock.lang.Ignore
import spock.lang.IgnoreIf
import spock.lang.Unroll

import java.nio.charset.StandardCharsets
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.startsWith
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat
import static org.junit.Assert.assertTrue

@IgnoreIf({ properties['test.deployment.env'] != "idp" })
class AuthConsentConfirmSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("USER_CONSENT_ENDPOINT")
    @Feature("UI_CONSENT_VIEW")
    def "Consent with authentication results"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response response = Steps.authenticateWithMid(flow,"60001017716", "69100366")
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())
        List<String> identityFields = response.body().htmlPath().getList("**.findAll {th -> th.@colspan == '1'}.b")
        assertTrue(response.body().htmlPath().getList("**.findAll { it.@method == 'POST'}.button").contains("Nõustun"))
        assertTrue(response.body().htmlPath().getList("**.findAll { it.@method == 'POST'}.button").contains("Keeldun"))
        assertTrue(identityFields.containsAll("Isikukood:", "Perenimi:", "Eesnimi:", "Sünniaeg:"))
        assertThat(response.body().htmlPath().getString("**.find { it.@id == 'natural-person-id-code'}"), equalTo("60001017716"))
        assertThat(response.body().htmlPath().getString("**.find { it.@id == 'natural-person-surname'}"), equalTo("TESTNUMBER"))
        assertThat(response.body().htmlPath().getString("**.find { it.@id == 'natural-person-given-name'}"), equalTo("ONE"))
        assertThat(response.body().htmlPath().getString("**.find { it.@id == 'natural-person-date-of-birth'}"), equalTo("01.01.2000"))
    }

    @Unroll
    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent with authentication results. Invalid session ID"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Requests.startMidAuthentication(flow, "60001017716", "69100366")
        Steps.pollMidResponse(flow)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        flow.setSessionId("1234567")
        Response response = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }

    @Ignore // TARA2-76 , TARA2-165
    @Unroll
    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent with authentication results. Invalid method post"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Requests.startMidAuthentication(flow, "60001017716", "69100366")
        Steps.pollMidResponse(flow)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        String location = oidcServiceResponse.getHeader("location")
        Response response = Requests.postRequestWithSessionId(flow, location)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), equalTo("Request method 'POST' not supported"))
    }

    @Unroll
    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent with authentication results. Missing session ID"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Requests.startMidAuthentication(flow, "60001017716", "69100366")
        Steps.pollMidResponse(flow)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        Response response = Steps.followRedirect(flow, oidcServiceResponse)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }

    @Unroll
    @Feature("USER_CONSENT_ENDPOINT")
    def "Consent with authentication results. #label"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Requests.startMidAuthentication(flow,"60001017716", "69100366")
        Steps.pollMidResponse(flow)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        Steps.getOAuthCookies(flow, acceptResponse)

        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(cookiesMap, "SESSION", flow.sessionId)
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(paramsMap, paramName, paramValue)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(additionalParamsMap, additionalParamName, additionalParamValue)
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullConsentUrl, cookiesMap, paramsMap, additionalParamsMap)

        assertEquals("Correct HTTP status code is returned", statusCode, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), startsWith(errorMessage))

        where:
        paramName           | paramValue                               | additionalParamName | additionalParamValue | label                                                      || statusCode || errorMessage
        _                   | _                                        | _                   | _                    | "Missing parameter consent_challenge"                      || 400        || "Required String parameter 'consent_challenge' is not present"
        "consent_challenge" | _                                        | _                   | _                    | "Empty parameter consent_challenge value"                  || 400        || "authConsent.consentChallenge: only characters and numbers allowed"
        "consent_challenge" | RandomStringUtils.random(51, true, true) | _                   | _                    | "Too long consent_challenge"                               || 400        || "authConsent.consentChallenge: size must be between 0 and 50"
        "consent_challenge" | "342%26abz"                              | _                   | _                    | "Invalid symbols in the consent_challenge parameter value" || 400        || "authConsent.consentChallenge: only characters and numbers allowed"
        "consent_challenge" | "ABCD1234"                               | "consent_challenge" | "1234abc"            | "Multiple consent_challenge parameters"                    || 400        || "Multiple request parameters with the same name not allowed"
    }

    @Feature("USER_CONSENT_ENDPOINT")
    @Feature("USER_CONSENT_POST_ACCEPT")
    def "Consent with invalid consent challenge value"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Requests.startMidAuthentication(flow,"60001017716", "69100366")
        Steps.pollMidResponse(flow)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        Steps.getOAuthCookies(flow, acceptResponse)

        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(cookiesMap, "SESSION", flow.sessionId)
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(paramsMap, "consent_challenge", RandomStringUtils.random(50, true, true))
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullConsentUrl, cookiesMap, paramsMap, Collections.emptyMap())
        flow.setCsrf(response.body().htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        Response consentConfirmResponse = Steps.submitConsent(flow, true)
        assertEquals("Correct HTTP status code is returned", 500, consentConfirmResponse.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", consentConfirmResponse.getContentType())
        assertThat(consentConfirmResponse.body().jsonPath().get("message").toString(), startsWith("Autentimine ebaõnnestus teenuse tehnilise vea tõttu."))
        assertThat(consentConfirmResponse.body().jsonPath().get("path").toString(), startsWith("/auth/consent/confirm"))
    }

    @Unroll
    @Feature("USER_CONSENT_CONFIRM_ENDPOINT")
    @Feature("USER_CONSENT_POST_ACCEPT")
    def "Confirm consent"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Steps.authenticateWithMid(flow,"60001017727" , "69200366")
        Response consentConfirmResponse = Steps.submitConsent(flow, true)
        assertEquals("Correct HTTP status code is returned", 302, consentConfirmResponse.statusCode())
        assertThat(consentConfirmResponse.getHeader("location"), startsWith(flow.oidcService.fullAuthenticationRequestUrl))
        assertThat(Utils.getParamValueFromResponseHeader(consentConfirmResponse, "state"), equalTo(flow.state))
        assertThat("Session cookie is invalidated", consentConfirmResponse.getCookie("SESSION"), equalTo(""))
    }

    @Unroll
    @Feature("USER_CONSENT_CONFIRM_ENDPOINT")
    def "Confirm consent with authentication results. Invalid session ID"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response oidcServiceResponse = Steps.authenticateWithMid(flow,"60001017727" , "69200366")
        assertEquals("Correct HTTP status code is returned", 200, oidcServiceResponse.statusCode())
        flow.setSessionId("1234567")
        Response response = Steps.submitConsent(flow, true)
        assertEquals("Correct HTTP status code is returned", 403, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertThat(response.body().jsonPath().get("error").toString(), equalTo("Forbidden"))
        String message = "Keelatud päring. Päring esitati topelt, sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."
        assertThat(response.body().jsonPath().get("message").toString(), equalTo(message))
    }

    @Ignore // TARA2-76 , TARA2-165
    @Unroll
    @Feature("USER_CONSENT_CONFIRM_ENDPOINT")
    def "Confirm consent with authentication results. Invalid method get"() {
        expect:
        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(cookiesMap, "SESSION", "1234567")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(paramsMap, "consent_given", true)
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullConsentConfirmUrl, cookiesMap, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertEquals("Correct error message is returned", "Request method 'GET' not supported", response.body().jsonPath().get("message"))
    }

    @Unroll
    @Feature("USER_CONSENT_CONFIRM_ENDPOINT")
    def "Confirm consent with authentication results. Missing session ID"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Steps.authenticateWithMid(flow,"60001017727" , "69200366")

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(paramsMap, "consent_given", true)
        def map3 = Utils.setParameter(paramsMap, "_csrf", flow.csrf)
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullConsentConfirmUrl, Collections.emptyMap(), paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 403, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertThat(response.body().jsonPath().get("error").toString(), equalTo("Forbidden"))
        String message = "Keelatud päring. Päring esitati topelt, sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."
        assertThat(response.body().jsonPath().get("message").toString(), equalTo(message))
    }

    @Unroll
    @Feature("USER_CONSENT_CONFIRM_ENDPOINT")
    def "Confirm consent with authentication results. #label"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Steps.authenticateWithMid(flow,"60001017727" , "69200366")

        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(cookiesMap, "SESSION", flow.sessionId)
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(paramsMap, paramName, paramValue)
        def map4 = Utils.setParameter(paramsMap, "_csrf", flow.csrf)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(additionalParamsMap, additionalParamName, additionalParamValue)
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullConsentConfirmUrl, cookiesMap, paramsMap, additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", statusCode, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertEquals("Correct error message is returned", errorMessage, response.body().jsonPath().get("message"))

        where:
        paramName       | paramValue | additionalParamName | additionalParamValue | label                                 || statusCode || errorMessage
        _               | _          | _                   | _                    | "Missing parameter consent_given"     || 400        || "Required String parameter 'consent_given' is not present"
        "consent_given" | _          | _                   | _                    | "Empty parameter consent_given value" || 400        || "authConsentConfirm.consentGiven: supported values are: 'true', 'false'"
        "consent_given" | "abc123"   | _                   | _                    | "Invalid consent_given value"         || 400        || "authConsentConfirm.consentGiven: supported values are: 'true', 'false'"
        "consent_given" | "false"    | "consent_given"     | "true"               | "Multiple consent_given parameters"   || 400        || "Multiple request parameters with the same name not allowed"
    }

    @Unroll
    @Feature("USER_CONSENT_POST_REJECT")
    def "Reject consent with authentication results"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Steps.authenticateWithMid(flow,"60001017716", "69100366")
        Response consentRejectResult = Steps.submitConsent(flow, false)
        assertEquals("Correct HTTP status code is returned", 302, consentRejectResult.statusCode())
        assertThat("Session cookie is invalidated", consentRejectResult.getCookie("SESSION"), equalTo(""))
        Response response = Steps.followRedirectWithCookies(flow, consentRejectResult, flow.oidcClient.cookies)
        assertEquals("Correct error value", "user_cancel", Utils.getParamValueFromResponseHeader(response, "error"))
        String actualErrorDescription = URLDecoder.decode(Utils.getParamValueFromResponseHeader(response, "error_description"), StandardCharsets.UTF_8)
        String errorDescription = "Consent not given. User canceled the authentication process."
        assertEquals("Correct error_description value", errorDescription, actualErrorDescription)
        assertThat(Utils.getParamValueFromResponseHeader(response, "state"), equalTo(flow.state))
  }

}
