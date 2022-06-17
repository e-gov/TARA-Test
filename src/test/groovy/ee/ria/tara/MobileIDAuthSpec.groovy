package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Ignore
import spock.lang.Unroll
import org.hamcrest.Matchers
import org.apache.commons.lang.RandomStringUtils

import static org.hamcrest.Matchers.equalTo
import static org.junit.jupiter.api.Assertions.*
import static org.hamcrest.MatcherAssert.assertThat

class MobileIDAuthSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("MID_INIT_ENDPOINT")
    def "initialize mobile-ID authentication"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", additionalParamsMap)
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", initMidAuthenticationSession.getContentType(), "Correct Content-Type is returned")
        String controlCode = initMidAuthenticationSession.body().htmlPath().getString("**.find { p -> p.@class == 'control-code' }.text()")
        assertEquals(4, controlCode.size(), "Verification code exists")
    }

    @Ignore // TARA2-80 , TARA2-165
    @Feature("MID_INIT_ENDPOINT")
    def "initialize mobile-ID authentication with invalid method get"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "idCode", "60001017716")
        def map2 = Utils.setParameter(paramsMap, "telephoneNumber", "69100366")
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(cookieMap, "SESSION", flow.sessionId)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullMidInitUrl, cookieMap, paramsMap, additionalParamsMap)
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertThat(response.body().jsonPath().get("message").toString(), equalTo("Request method 'GET' not supported"))
    }

    @Unroll
    @Feature("MID_INIT_ENDPOINT")
    @Feature("MID_VALID_INPUT_IDCODE")
    @Feature("MID_VALID_INPUT_TEL")
    def "initialize mobile-ID authentication with invalid params: #label"() {
        expect:
        LinkedHashMap<String, String> additionalParamsMap = (LinkedHashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(additionalParamsMap, additionalParameterName, additionalParameterValue)
        Steps.startAuthenticationInTara(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, idCode, phoneNo, additionalParamsMap)
        assertEquals(400, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", initMidAuthenticationSession.getContentType(), "Correct Content-Type is returned")
        assertThat(initMidAuthenticationSession.body().jsonPath().get("message"), Matchers.containsString(errorMessage))

        where:
        phoneNo                                   | idCode         | additionalParameterName | additionalParameterValue               | label                                 || errorMessage
        "00000266"                                | "60001019938"  | _                       | _                                      | "invalid idCode checksum"             || "Isikukood ei ole korrektne."
        "+37200000266"                            | "60001019939"  | _                       | _                                      | "invalid telephone number"            || "Telefoninumber ei ole korrektne."
        _                                         | _              | _                       | _                                      | "missing telephone number and idCode" || "Isikukood ei ole korrektne.; Telefoninumber ei ole korrektne."
        "00000266"                                | _              | _                       | _                                      | "missing idCode"                      || "Isikukood ei ole korrektne."
        _                                         | "60001019939"  | _                       | _                                      | "missing telephone number"            || "Telefoninumber ei ole korrektne."
        "00000266"                                | "600010199399" | _                       | _                                      | "too long idCode"                     || "Isikukood ei ole korrektne."
        "00000266"                                | "60001329939"  | _                       | _                                      | "wrong date inside idCode"            || "Isikukood ei ole korrektne."
        "00000266"                                | "6000"         | _                       | _                                      | "too short idCode"                    || "Isikukood ei ole korrektne."
        "abcd"                                    | "ABCD"         | _                       | _                                      | "invalid telephone number and idCode" || "Isikukood ei ole korrektne.; Telefoninumber ei ole korrektne."
        "00000266"                                | "38500030556"  | _                       | _                                      | "invalid month in idCode"             || "Isikukood ei ole korrektne."
        "45"                                      | "60001019939"  | _                       | _                                      | "too short telephone number"          || "Telefoninumber ei ole korrektne."
        RandomStringUtils.random(16, false, true) | "60001019939"  | _                       | _                                      | "too long telephone number"           || "Telefoninumber ei ole korrektne."
        "69100366"                                | "60001017716"  | "idCode"                | "60001017727"                          | "multiple idCode parameters"          || "Multiple request parameters with the same name not allowed"
        "69100366"                                | "60001017716"  | "telephoneNumber"       | "00000766"                             | "multiple telephoneNumber parameters" || "Multiple request parameters with the same name not allowed"
        "69100366"                                | "60001017716"  | "_csrf"                 | "d7860443-a0cc-45db-ad68-3c9300c0b3bb" | "multiple _csrf parameters"           || "Multiple request parameters with the same name not allowed"
    }

    @Unroll
    @Feature("MID_AUTH_POLL_RESPONSE_COMPLETE")
    @Feature("MID_VALID_INPUT_TEL")
    @Feature("MID_AUTH_FAILED")
    def "initialize mobile-ID authentication with scenario: #label et"() {
        expect:
        LinkedHashMap<String, String> additionalParamsMap = (LinkedHashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(additionalParamsMap, additionalParameterName, additionalParameterValue)
        Steps.startAuthenticationInTara(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, idCode, phoneNo, additionalParamsMap)
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response pollResponse = Steps.pollMidResponse(flow, 3000L)
        String messageText = "Correct HTTP status code is returned. Response body: " + pollResponse.body().jsonPath().prettify()
        assertEquals(400, pollResponse.statusCode(), messageText)
        assertEquals("application/json;charset=UTF-8", pollResponse.getContentType(), "Correct Content-Type is returned")
        assertThat(pollResponse.body().jsonPath().get("message"), Matchers.startsWith(errorMessage))
        assertThat(pollResponse.body().jsonPath().get("reportable"), Matchers.is(reportable))

        where:
        phoneNo                                   | idCode        | additionalParameterName | additionalParameterValue | reportable | label                                            || errorMessage
        "00000266"                                | "60001019939" | _                       | _                        | false      | "Mobile-ID user has no active certificates"      || "Kasutajal pole telefoninumbril Mobiil-ID lepingut."
        "07110066"                                | "60001019947" | _                       | _                        | false      | "Sending authentication request to phone failed" || "Kasutaja mobiiltelefoni ei saa Mobiil-ID autentimise sõnumeid saata."
        "01100266"                                | "60001019950" | _                       | _                        | false      | "User cancelled authentication"                  || "Kasutaja katkestas mobiiltelefonil Mobiil-ID autentimise."
        "00000666"                                | "60001019961" | _                       | _                        | true       | "Created signature is not valid"                 || "Autentimine Mobiil-ID-ga ei õnnestunud."
        "01200266"                                | "60001019972" | _                       | _                        | false      | "Phone cannot receive Mobile-ID auth messages"   || "Kasutaja mobiiltelefoni ei saa Mobiil-ID autentimise sõnumeid saata."
        "13100266"                                | "60001019983" | _                       | _                        | false      | "Phone is not in coverage area"                  || "Kasutaja mobiiltelefon on levialast väljas."
        "66000266"                                | "50001018908" | _                       | _                        | false      | "User timeout"                                   || ""
        RandomStringUtils.random(15, false, true) | "60001019939" | _                       | _                        | false      | "Telephone number length check"                  || "Kasutajal pole telefoninumbril Mobiil-ID lepingut."
    }

    @Unroll
    @Feature("MID_AUTH_POLL_RESPONSE_COMPLETE")
    def "initialize mobile-ID authentication with scenario: #label ru"() {
        expect:
        LinkedHashMap<String, String> localeMap = (LinkedHashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(localeMap, "lang", "ru")
        Response initOIDCServiceSession = Steps.startAuthenticationInOidc(flow)
        Response loginSession = Steps.initLoginSession(flow, initOIDCServiceSession, localeMap)
        LinkedHashMap<String, String> additionalParamsMap = (LinkedHashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(additionalParamsMap, additionalParameterName, additionalParameterValue)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, idCode, phoneNo, additionalParamsMap)
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response pollResponse = Steps.pollMidResponse(flow, 3000L)
        assertEquals(400, pollResponse.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", pollResponse.getContentType(), "Correct Content-Type is returned")
        assertThat(pollResponse.body().jsonPath().get("message"), Matchers.startsWith(errorMessage))
        assertThat(pollResponse.body().jsonPath().get("reportable"), Matchers.is(reportable))

        where:
        phoneNo    | idCode        | additionalParameterName | additionalParameterValue | reportable | label                                            || errorMessage
        "00000266" | "60001019939" | _                       | _                        | false      | "Mobile-ID user has no active certificates"      || "У пользователя отсутствует договор об услуге"
        "07110066" | "60001019947" | _                       | _                        | false      | "Sending authentication request to phone failed" || "На телефон пользователя нельзя отправить сообщение аутентификации Mobiil-ID."
        "01100266" | "60001019950" | _                       | _                        | false      | "User cancelled authentication"                  || "Пользователь отменил аутентификацию с Mobiil-ID на своем телефоне."
        "00000666" | "60001019961" | _                       | _                        | true       | "Created signature is not valid"                 || "Аутентификация с помощью Вашего"
        "01200266" | "60001019972" | _                       | _                        | false      | "Phone cannot receive Mobile-ID auth messages"   || "На телефон пользователя нельзя отправить сообщение аутентификации Mobiil-ID."
        "13100266" | "60001019983" | _                       | _                        | false      | "Phone is not in coverage area"                  || "Телефон пользователя находится вне зоны доступа."
        "66000266" | "50001018908" | _                       | _                        | false      | "User timeout"                                   || "Пользователь не прошел аутентификацию на телефоне в течение требуемого времени. Пожалуйста, попробуйте еще раз."
    }

    @Unroll
    @Feature("MID_AUTH_POLL_RESPONSE_COMPLETE")
    def "initialize mobile-ID authentication with scenario: #label en"() {
        expect:
        LinkedHashMap<String, String> localeMap = (LinkedHashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(localeMap, "lang", "en")
        Response initOIDCServiceSession = Steps.startAuthenticationInOidc(flow)
        Response loginSession = Steps.initLoginSession(flow, initOIDCServiceSession, localeMap)
        LinkedHashMap<String, String> additionalParamsMap = (LinkedHashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(additionalParamsMap, additionalParameterName, additionalParameterValue)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, idCode, phoneNo, additionalParamsMap)
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response pollResponse = Steps.pollMidResponse(flow, 3000L)
        assertEquals(400, pollResponse.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", pollResponse.getContentType(), "Correct Content-Type is returned")
        assertThat(pollResponse.body().jsonPath().get("message"), Matchers.startsWith(errorMessage))
        assertThat(pollResponse.body().jsonPath().get("reportable"), Matchers.is(reportable))

        where:
        phoneNo    | idCode        | additionalParameterName | additionalParameterValue | reportable | label                                            || errorMessage
        "00000266" | "60001019939" | _                       | _                        | false      | "Mobile-ID user has no active certificates"      || "User has no Mobile-ID contract with this phone number."
        "07110066" | "60001019947" | _                       | _                        | false      | "Sending authentication request to phone failed" || "User's mobile phone cannot receive Mobile-ID authentication messages."
        "01100266" | "60001019950" | _                       | _                        | false      | "User cancelled authentication"                  || "User cancelled Mobile-ID authentication on mobile phone."
        "00000666" | "60001019961" | _                       | _                        | true       | "Created signature is not valid"                 || "Authentication with Mobile-ID failed. Test your Mobile-ID with the DigiDoc4 client"
        "01200266" | "60001019972" | _                       | _                        | false      | "Phone cannot receive Mobile-ID auth messages"   || "User's mobile phone cannot receive Mobile-ID authentication messages."
        "13100266" | "60001019983" | _                       | _                        | false      | "Phone is not in coverage area"                  || "User's mobile phone is out of the coverage area."
        "66000266" | "50001018908" | _                       | _                        | false      | "User timeout"                                   || "User did not authenticate on mobile phone during the required time. Please try again."
    }

    @Unroll
    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("MID_AUTH_PENDING")
    def "poll mobile-ID authentication session"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", additionalParamsMap)
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response response = Requests.pollMid(flow)
        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertEquals("PENDING", response.body().jsonPath().get("status"), "Correct Mobile-ID status")
    }

    @Unroll
    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    def "poll mobile-ID authentication session with invalid session ID"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", additionalParamsMap)
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        flow.setSessionId("1234567")
        Response response = Requests.pollMid(flow)
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertEquals("Teie seanssi ei leitud! Seanss aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"), "Correct error message is returned")
    }

    @Unroll
    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("MID_AUTH_SUCCESS")
    def "poll mobile-ID authentication with session complete"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", additionalParamsMap)
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        sleep(10000)
        Response response = Requests.pollMid(flow)
        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertEquals("COMPLETED", response.body().jsonPath().get("status"), "Correct Mobile-ID status")
    }

    @Ignore // TARA2-80 , TARA2-165
    @Unroll
    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    def "poll mobile-ID authentication with invalid method post"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", additionalParamsMap)
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullMidPollUrl)
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertThat(response.body().jsonPath().get("message").toString(), equalTo("Request method 'POST' not supported"))
    }

    @Unroll
    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("MID_AUTH_CANCELED")
    def "cancel mobile-ID authentication"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", additionalParamsMap)
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullMidCancelUrl)
        assertEquals(302, response.statusCode(), "Correct HTTP status code is returned")
        assertThat(response.getHeader("location"), Matchers.startsWith(flow.loginService.initUrl + "?login_challenge=" + flow.loginChallenge))
    }

    @Unroll
    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Verify cancel mobile-ID authentication response headers"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", additionalParamsMap)
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullMidCancelUrl)
        assertEquals(302, response.statusCode(), "Correct HTTP status code is returned")
        Steps.verifyResponseHeaders(response)
    }

    @Unroll
    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    def "cancel mobile-ID authentication with invalid session ID"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", additionalParamsMap)
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")

        flow.setSessionId("1234567")
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullMidCancelUrl)
        assertEquals(403, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        // _csrf is directly related with SESSION cookie
        assertThat(response.body().jsonPath().get("error").toString(), equalTo("Forbidden"))
        String message = "Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."
        assertThat(response.body().jsonPath().get("message").toString(), equalTo(message))
    }

    @Ignore //TARA2-80 , TARA2-165
    @Unroll
    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    def "cancel mobile-ID authentication with invalid method get"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", additionalParamsMap)
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response response = Requests.getRequestWithSessionId(flow, flow.loginService.fullMidCancelUrl)
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertThat(response.body().jsonPath().get("message").toString(), equalTo("Request method 'GET' not supported"))
    }
}
