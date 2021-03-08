package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Ignore
import spock.lang.IgnoreIf
import spock.lang.Unroll
import org.hamcrest.Matchers

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat

@IgnoreIf({ properties['test.deployment.env'] == "idp" })
class SmartIDAuthSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("SID_AUTH_INIT_ENDPOINT")
    def "initialize Smart-ID authentication"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, "10101010005", additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initSidAuthenticationSession.statusCode())
        assertEquals("Correct Content-Type is returned", "text/html;charset=UTF-8", initSidAuthenticationSession.getContentType())
        String controlCode = initSidAuthenticationSession.body().htmlPath().getString("**.find { p -> p.@class == 'control-code' }.text()")
        assertEquals("Verification code exists", 4, controlCode.size())
    }

    @Ignore // TARA2-165
    @Unroll
    @Feature("SID_AUTH_INIT_ENDPOINT")
    def "initialize Smart-ID authentication with invalid method get"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "idCode", "10101010005")
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(cookieMap, "SESSION", flow.sessionId)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullSidInitUrl, cookieMap, paramsMap, additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("Request method 'GET' not supported"))
    }

    @Unroll
    @Feature("SID_AUTH_INIT_ENDPOINT")
    @Feature("SID_AUTH_CHECKS_IDCODE")
    def "initialize Smart-ID authentication with invalid params: #label"() {
        expect:
        LinkedHashMap<String, String> additionalParamsMap = (LinkedHashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(additionalParamsMap, additionalParameterName, additionalParameterValue)
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, idCode, additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 400, initSidAuthenticationSession.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", initSidAuthenticationSession.getContentType())
        assertThat(initSidAuthenticationSession.body().jsonPath().get("message"), Matchers.containsString(errorMessage))

        where:
        idCode         | additionalParameterName | additionalParameterValue               | label                        || errorMessage
        "60001019938"  | _                       | _                                      | "invalid idCode checksum"    || "Isikukood ei ole korrektne."
        _              | _                       | _                                      | "missing idCode"             || "Isikukood ei ole korrektne."
        "600010199399" | _                       | _                                      | "too long idCode"            || "Isikukood ei ole korrektne."
        "60001329939"  | _                       | _                                      | "wrong date inside idCode"   || "Isikukood ei ole korrektne."
        "6000"         | _                       | _                                      | "too short idCode"           || "Isikukood ei ole korrektne."
        "38500030556"  | _                       | _                                      | "invalid month in idCode"    || "Isikukood ei ole korrektne."
        "60001017716"  | "idCode"           | "60001017727"                          | "multiple idCode parameters" || "Multiple request parameters with the same name not allowed"
        "60001017716"  | "_csrf"                 | "d7860443-a0cc-45db-ad68-3c9300c0b3bb" | "multiple _csrf parameters"  || "Multiple request parameters with the same name not allowed"
    }

    @Unroll
    @Feature("SID_AUTH_POLL_RESPONSE_COMPLETED_ERRORS")
    def "initialize Smart-ID authentication with scenario: #label et"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, idCode, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initSidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollSidResponse(flow)
        String messageText = "Correct HTTP status code is returned. Response body: " + pollResponse.body().prettyPrint()
        assertEquals(messageText, 400, pollResponse.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", pollResponse.getContentType())
        assertThat(pollResponse.body().jsonPath().get("message"), Matchers.startsWith(errorMessage))

        where:
        idCode        | label            || errorMessage
        "10101010016" | "User cancelled" || "Autentimine katkestati kasutaja poolt."
        "10101010027" | "Timeout"        || "Autentimise päring aegus."
    }

    @Unroll
    @Feature("SID_AUTH_POLL_RESPONSE_COMPLETED_ERRORS")
    def "initialize Smart-ID authentication with scenario: #label en"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid", "en")
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, idCode, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initSidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollSidResponse(flow)
        String messageText = "Correct HTTP status code is returned. Response body: " + pollResponse.body().prettyPrint()
        assertEquals(messageText, 400, pollResponse.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", pollResponse.getContentType())
        assertThat(pollResponse.body().jsonPath().get("message"), Matchers.startsWith(errorMessage))

        where:
        idCode        | label            || errorMessage
        "10101010016" | "User cancelled" || "Authentication was cancelled by user."
        "10101010027" | "Timeout"        || "Authentication request timed out."
    }

    @Unroll
    @Feature("SID_AUTH_POLL_RESPONSE_COMPLETED_ERRORS")
    def "initialize Smart-ID authentication with scenario: #label ru"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid", "ru")
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, idCode, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initSidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollSidResponse(flow)
        String messageText = "Correct HTTP status code is returned. Response body: " + pollResponse.body().prettyPrint()
        assertEquals(messageText, 400, pollResponse.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", pollResponse.getContentType())
        assertThat(pollResponse.body().jsonPath().get("message"), Matchers.startsWith(errorMessage))

        where:
        idCode        | label            || errorMessage
        "10101010016" | "User cancelled" || "Пользователь рервал аутентификацию."
        "10101010027" | "Timeout"        || "Истекло время запроса."
    }

    @Unroll
    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("SID_AUTH_PENDING")
    def "poll Smart-ID authentication session"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, "10101010027", additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initSidAuthenticationSession.statusCode())
        Response response = Requests.pollSid(flow)
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertEquals("Correct Mobile-ID status", "PENDING", response.body().jsonPath().get("status"))
    }

    @Unroll
    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    def "poll Smart-ID authentication session with invalid session ID"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, "10101010027", additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initSidAuthenticationSession.statusCode())
        flow.setSessionId("1234567")
        Response response = Requests.pollSid(flow)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }

    @Unroll
    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("SID_AUTH_SUCCESS")
    def "poll Smart-ID authentication with session complete"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, "10101010005", additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initSidAuthenticationSession.statusCode())
        Response response = Steps.pollSidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertEquals("Correct Mobile-ID status", "COMPLETED", response.body().jsonPath().get("status"))
    }

    @Ignore // TARA2-165
    @Unroll
    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    def "poll Smart-ID authentication with invalid method post"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, "10101010005", additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initSidAuthenticationSession.statusCode())
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullSidPollUrl)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("Request method 'POST' not supported"))
    }

    @Unroll
    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("SID_AUTH_CANCELED")
    def "cancel Smart-ID authentication"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, "10101010005", additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initSidAuthenticationSession.statusCode())
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullSidCancelUrl)
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        assertThat(response.getHeader("location"), Matchers.startsWith(flow.loginService.initUrl + "?login_challenge=" + flow.loginChallenge))
    }

    @Unroll
    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Verify cancel Smart-ID authentication response headers"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, "10101010005", additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initSidAuthenticationSession.statusCode())
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullSidCancelUrl)
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        Steps.verifyResponseHeaders(response)
    }

    @Unroll
    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    def "cancel Smart-ID authentication with invalid session ID"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, "10101010005", additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initSidAuthenticationSession.statusCode())

        flow.setSessionId("1234567")
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullSidCancelUrl)
        assertEquals("Correct HTTP status code is returned", 403, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())

        assertEquals("Correct error text is returned", "Forbidden", response.body().jsonPath().get("error"))
        String errorMessage = "Keelatud päring. Päring esitati topelt, sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."
        assertEquals("Correct error message is returned", errorMessage, response.body().jsonPath().get("message"))
    }

    @Ignore // TARA2-165
    @Unroll
    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    def "cancel Smart-ID authentication with invalid method get"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, "10101010005", additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initSidAuthenticationSession.statusCode())

        Response response = Requests.getRequestWithSessionId(flow, flow.loginService.fullSidCancelUrl)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("Request method 'GET' not supported"))
    }
}
