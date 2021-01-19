package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Ignore
import spock.lang.Unroll
import org.hamcrest.Matchers
import org.apache.commons.lang.RandomStringUtils

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat

class MobileIDAuthSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("MID_INIT_ENDPOINT")
    def "initialize mobile-ID authentication"() {
        expect:
        Steps.initAuthenticationSession(flow)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        assertEquals("Correct Content-Type is returned", "text/html;charset=UTF-8", initMidAuthenticationSession.getContentType())
        String controlCode = initMidAuthenticationSession.body().htmlPath().getString("**.find { p -> p.@class == 'control-code' }.text()")
        assertEquals("Verification code exists", 4, controlCode.size())
    }

    @Ignore // TARA2-80 , TARA2-165
    @Feature("MID_INIT_ENDPOINT")
    def "initialize mobile-ID authentication with invalid method get"() {
        expect:
        Steps.initAuthenticationSession(flow)
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "idCode", "60001017716")
        def map2 = Utils.setParameter(paramsMap, "telephoneNumber", "69100366")
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(cookieMap, "SESSION", flow.sessionId)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullMidInitUrl, cookieMap, paramsMap, additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("Request method 'GET' not supported"))
    }

    @Ignore
    // https://jira.ria.ee/browse/TARA2-80
    @Feature("MID_INIT_ENDPOINT")
    def "initialize mobile-ID authentication with unsupported Content-Type"() {
        expect:
        Steps.initAuthenticationSession(flow)
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "idCode", "60001017716")
        def map2 = Utils.setParameter(paramsMap, "telephoneNumber", "69100366")
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(cookieMap, "SESSION", flow.sessionId)
        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        def map4 = Utils.setParameter(headersMap, "Content-Type", "application/xml")
        Response response = Requests.postRequestWithHeadersCookiesAndParams(flow, flow.loginService.fullMidInitUrl, headersMap, cookieMap, paramsMap)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("Invalid content type"))
    }

    @Unroll
    @Feature("MID_INIT_ENDPOINT")
    @Feature("MID_VALID_INPUT_IDCODE")
    @Feature("MID_VALID_INPUT_TEL")
    def "initialize mobile-ID authentication with invalid params: #label"() {
        expect:
        LinkedHashMap<String, String> additionalParamsMap = (LinkedHashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(additionalParamsMap, additionalParameterName, additionalParameterValue)
        Steps.initAuthenticationSession(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, idCode, phoneNo, additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 400, initMidAuthenticationSession.statusCode())
        assertThat(initMidAuthenticationSession.body().jsonPath().get("message"), Matchers.containsString(errorMessage))

        where:
        phoneNo                                   | idCode         | additionalParameterName | additionalParameterValue | label                                 || errorMessage
        "00000266"                                | "60001019938"  | _                       | _                        | "invalid idCode checksum"             || "Isikukood ei ole korrektne."
        "+37200000266"                            | "60001019939"  | _                       | _                        | "invalid telephone number"            || "Telefoninumber ei ole korrektne."
     // TARA2-80  _                                         | _              | _                       | _                        | "missing telephone number and idCode" || "Telefoninumber ei ole korrektne.; Isikukood ei ole korrektne."
        _                                         | _              | _                       | _                        | "missing telephone number and idCode" || "Telefoninumber ei ole korrektne."
        "00000266"                                | _              | _                       | _                        | "missing idCode"                      || "Isikukood ei ole korrektne."
        _                                         | "60001019939"  | _                       | _                        | "missing telephone number"            || "Telefoninumber ei ole korrektne."
        "00000266"                                | "600010199399" | _                       | _                        | "too long idCode"                     || "Isikukood ei ole korrektne."
        "00000266"                                | "6000"         | _                       | _                        | "too short idCode"                    || "Isikukood ei ole korrektne."
       // TARA2-80 "abcd"                                    | "ABCD"         | _                       | _                        | "invalid telephone number and idCode" || "Isikukood ei ole korrektne.; Telefoninumber ei ole korrektne."
        "abcd"                                    | "ABCD"         | _                       | _                        | "invalid telephone number and idCode" || "Isikukood ei ole korrektne."
        "00000266"                                | "38500030556"  | _                       | _                        | "invalid month in idCode"             || "Isikukood ei ole korrektne."
        "12345"                                   | "60001019939"  | _                       | _                        | "too short telephone number"          || "Telefoninumber ei ole korrektne."
        RandomStringUtils.random(16, false, true) | "60001019939"  | _                       | _                        | "too long telephone number"           || "Telefoninumber ei ole korrektne."
    }

    @Ignore // thread pool issue
    @Unroll
    @Feature("MID_AUTH_POLL_RESPONSE_COMPLETE")
    @Feature("MID_VALID_INPUT_TEL")
    def "initialize mobile-ID authentication with scenario: #label et"() {
        expect:
        LinkedHashMap<String, String> additionalParamsMap = (LinkedHashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(additionalParamsMap, additionalParameterName, additionalParameterValue)
        Steps.initAuthenticationSession(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, idCode, phoneNo, additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 400, pollResponse.statusCode())
        assertThat(pollResponse.body().jsonPath().get("message"), Matchers.startsWith(errorMessage))

        where:
        phoneNo                                   | idCode        | additionalParameterName | additionalParameterValue | label                                            || errorMessage
        "00000266"                                | "60001019939" | _                       | _                        | "Mobile-ID user has no active certificates"      || "Kasutajal pole Mobiil-ID lepingut."
        "07110066"                                | "60001019947" | _                       | _                        | "Sending authentication request to phone failed" || "Teie mobiiltelefoni ei saa Mobiil-ID autentimise sõnumeid saata."
        "01100266"                                | "60001019950" | _                       | _                        | "User cancelled authentication"                  || "Autentimine on katkestatud."
        "00000666"                                | "60001019961" | _                       | _                        | "Created signature is not valid"                 || "Autentimine Mobiil-ID-ga ei õnnestunud. Testi oma Mobiil-ID toimimist DigiDoc4 kliendis:"
  // TARA2-80      "01200266"                                | "60001019972" | _                       | _                        | "SIM application error"                          || "Teie mobiiltelefoni SIM kaardiga tekkis tõrge."
        "13100266"                                | "60001019983" | _                       | _                        | "Phone is not in coverage area"                  || "Teie mobiiltelefon on levialast väljas."
        RandomStringUtils.random(15, false, true) | "60001019939" | _                       | _                        | "Telephone number length check"                  || "Kasutajal pole Mobiil-ID lepingut."
    }

    @Ignore //TARA2-80
    @Unroll
    @Feature("MID_AUTH_POLL_RESPONSE_COMPLETE")
    def "initialize mobile-ID authentication with scenario: #label ru"() {
        expect:
        LinkedHashMap<String, String> localeMap = (LinkedHashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(localeMap, "lang", "ru")
        Response initOIDCServiceSession = Steps.createSession(flow)
        Response loginSession = Steps.initLoginSession(flow, initOIDCServiceSession, localeMap)
        LinkedHashMap<String, String> additionalParamsMap = (LinkedHashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(additionalParamsMap, additionalParameterName, additionalParameterValue)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, idCode, phoneNo, additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 400, pollResponse.statusCode())
        assertThat(pollResponse.body().jsonPath().get("message"), Matchers.startsWith(errorMessage))

        where:
        phoneNo    | idCode        | additionalParameterName | additionalParameterValue | label                                            || errorMessage
        "00000266" | "60001019939" | _                       | _                        | "Mobile-ID user has no active certificates"      || "У пользователя отсутствует договор об услуге"
        "07110066" | "60001019947" | _                       | _                        | "Sending authentication request to phone failed" || "На Ваш телефон нельзя отправить сообщение аутентификации"
        "01100266" | "60001019950" | _                       | _                        | "User cancelled authentication"                  || "Аутентификация прервана"
        "00000666" | "60001019961" | _                       | _                        | "Created signature is not valid"                 || "Аутентификация с помощью Вашего"
        "01200266" | "60001019972" | _                       | _                        | "SIM application error"                          || "В SIM-карте Вашего телефона произошел сбой."
        "13100266" | "60001019983" | _                       | _                        | "Phone is not in coverage area"                  || "Ваш телефон находится вне зоны доступа."

    }

    @Ignore //TARA2-80
    @Unroll
    @Feature("MID_AUTH_POLL_RESPONSE_COMPLETE")
    def "initialize mobile-ID authentication with scenario: #label en"() {
        expect:
        LinkedHashMap<String, String> localeMap = (LinkedHashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(localeMap, "lang", "en")
        Response initOIDCServiceSession = Steps.createSession(flow)
        Response loginSession = Steps.initLoginSession(flow, initOIDCServiceSession, localeMap)
        LinkedHashMap<String, String> additionalParamsMap = (LinkedHashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(additionalParamsMap, additionalParameterName, additionalParameterValue)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, idCode, phoneNo, additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 400, pollResponse.statusCode())
        assertThat(pollResponse.body().jsonPath().get("message"), Matchers.startsWith(errorMessage))

        where:
        phoneNo    | idCode        | additionalParameterName | additionalParameterValue | label                                            || errorMessage
        "00000266" | "60001019939" | _                       | _                        | "Mobile-ID user has no active certificates"      || "The user has no Mobile-ID contract."
        "07110066" | "60001019947" | _                       | _                        | "Sending authentication request to phone failed" || "Your mobile phone cannot receive Mobile-ID authentication messages."
        "01100266" | "60001019950" | _                       | _                        | "User cancelled authentication"                  || "Authentication has been cancelled."
        "00000666" | "60001019961" | _                       | _                        | "Created signature is not valid"                 || "Authentication with Mobile-ID failed. Test your Mobile-ID with the DigiDoc4 client"
        "01200266" | "60001019972" | _                       | _                        | "SIM application error"                          || "There was an error with your SIM card."
        "13100266" | "60001019983" | _                       | _                        | "Phone is not in coverage area"                  || "Your mobile phone is out of coverage area."

    }

    @Unroll
    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("MID_AUTH_PENDING")
    def "poll mobile-ID authentication session"() {
        expect:
        Steps.initAuthenticationSession(flow)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response response = Requests.pollMid(flow)
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertEquals("Correct Mobile-ID status", "PENDING", response.body().jsonPath().get("status"))
    }

    @Unroll
    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    def "poll mobile-ID authentication session with invalid session ID"() {
        expect:
        Steps.initAuthenticationSession(flow)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        flow.setSessionId("1234567")
        Response response = Requests.pollMid(flow)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }

    @Unroll
    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("MID_AUTH_SUCCESS")
    def "poll mobile-ID authentication with session complete"() {
        expect:
        Steps.initAuthenticationSession(flow)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        sleep(10000)
        Response response = Requests.pollMid(flow)
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertEquals("Correct Mobile-ID status", "COMPLETED", response.body().jsonPath().get("status"))
    }

    @Ignore // TARA2-80
    @Unroll
    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    def "poll mobile-ID authentication with invalid method post"() {
        expect:
        Steps.initAuthenticationSession(flow)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullMidPollUrl)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("Request method 'POST' not supported"))
    }

    @Unroll
    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("MID_AUTH_CANCELED")
    def "cancel mobile-ID authentication"() {
        expect:
        Steps.initAuthenticationSession(flow)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullMidCancelUrl)
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        assertThat(response.getHeader("location"), Matchers.startsWith(flow.loginService.initUrl + "?login_challenge=" + flow.loginChallenge))
    }

    @Ignore
    @Unroll
    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    def "cancel mobile-ID authentication with invalid session ID"() {
        expect:
        Steps.initAuthenticationSession(flow)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())

        flow.setSessionId("1234567")
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullMidCancelUrl)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        // TODO "application/json;charset=UTF-8"
        assertEquals("Correct Content-Type is returned", "application/json", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }

    @Ignore //TARA2-80
    @Unroll
    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    def "cancel mobile-ID authentication with invalid method get"() {
        expect:
        Steps.initAuthenticationSession(flow)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response response = Requests.getRequestWithSessionId(flow, flow.loginService.fullMidCancelUrl)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("Request method 'GET' not supported"))
    }
}
