package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.commons.lang3.RandomStringUtils

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.startsWith

class MobileIDAuthSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Feature("MID_INIT_ENDPOINT")
    def "initialize mobile-ID authentication"() {
        given:
        Steps.startAuthenticationInTara(flow)

        when:
        Response response = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366")

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        assertThat("Correct Content-Type", response.contentType, is("text/html;charset=UTF-8"))
        String controlCode = response.htmlPath().getString("**.find { p -> p.@class == 'control-code' }.text()")
        assertThat("Verification code exists", controlCode.size(), is(4))
    }

    //TODO: AUT-630
    @Feature("MID_INIT_ENDPOINT")
    def "initialize mobile-ID authentication with invalid method get"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Map paramsMap = [
                "idCode"         : "60001017716",
                "telephoneNumber": "69100366"]
        Map cookieMap = [
                "SESSION": flow.sessionId]

        when:
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullMidInitUrl, cookieMap, paramsMap, [:])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_INTERNAL))
        assertThat("Correct message", response.jsonPath().getString('message'), is(MESSAGE_INTERNAL_ERROR))
    }

    @Feature("MID_INIT_ENDPOINT")
    @Feature("MID_VALID_INPUT_IDCODE")
    @Feature("MID_VALID_INPUT_TEL")
    def "initialize mobile-ID authentication with invalid params: #label"() {
        given:
        Map additionalParamsMap = [:]
        Utils.setParameter(additionalParamsMap, paramName, paramValue)
        Steps.startAuthenticationInTara(flow)

        when:
        Response response = Steps.initMidAuthSession(flow, flow.sessionId, idCode, phoneNo, additionalParamsMap)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString("message"), is(errorMessage))

        where:
        phoneNo                                   | idCode         | paramName         | paramValue                             | label                                 || errorMessage
        "00000266"                                | "60001019938"  | _                 | _                                      | "invalid idCode checksum"             || "Isikukood ei ole korrektne."
        "+37200000266"                            | "60001019939"  | _                 | _                                      | "invalid telephone number"            || "Telefoninumber ei ole korrektne."
        _                                         | _              | _                 | _                                      | "missing telephone number and idCode" || "Isikukood ei ole korrektne.; Telefoninumber ei ole korrektne."
        "00000266"                                | _              | _                 | _                                      | "missing idCode"                      || "Isikukood ei ole korrektne."
        _                                         | "60001019939"  | _                 | _                                      | "missing telephone number"            || "Telefoninumber ei ole korrektne."
        "00000266"                                | "600010199399" | _                 | _                                      | "too long idCode"                     || "Isikukood ei ole korrektne."
        "00000266"                                | "60001329939"  | _                 | _                                      | "wrong date inside idCode"            || "Isikukood ei ole korrektne."
        "00000266"                                | "6000"         | _                 | _                                      | "too short idCode"                    || "Isikukood ei ole korrektne."
        "abcd"                                    | "ABCD"         | _                 | _                                      | "invalid telephone number and idCode" || "Isikukood ei ole korrektne.; Telefoninumber ei ole korrektne."
        "00000266"                                | "38500030556"  | _                 | _                                      | "invalid month in idCode"             || "Isikukood ei ole korrektne."
        "45"                                      | "60001019939"  | _                 | _                                      | "too short telephone number"          || "Telefoninumber ei ole korrektne."
        RandomStringUtils.random(16, false, true) | "60001019939"  | _                 | _                                      | "too long telephone number"           || "Telefoninumber ei ole korrektne."
        "69100366"                                | "60001017716"  | "idCode"          | "60001017727"                          | "multiple idCode parameters"          || MESSAGE_DUPLICATE_PARAMETERS
        "69100366"                                | "60001017716"  | "telephoneNumber" | "00000766"                             | "multiple telephoneNumber parameters" || MESSAGE_DUPLICATE_PARAMETERS
        "69100366"                                | "60001017716"  | "_csrf"           | "d7860443-a0cc-45db-ad68-3c9300c0b3bb" | "multiple _csrf parameters"           || MESSAGE_DUPLICATE_PARAMETERS
    }

    @Feature("MID_AUTH_POLL_RESPONSE_COMPLETE")
    @Feature("MID_VALID_INPUT_TEL")
    @Feature("MID_AUTH_FAILED")
    def "initialize mobile-ID authentication with scenario: #label et"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, idCode, phoneNo)

        when:
        Response response = Steps.pollMidResponse(flow, 3000L)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString("message"), startsWith(errorMessage))
        assertThat("Correct reportable value", response.jsonPath().getBoolean("reportable"), is(reportable))

        where:
        phoneNo                                   | idCode        | reportable | label                                            || errorMessage
        "00000266"                                | "60001019939" | false      | "Mobile-ID user has no active certificates"      || "Kasutajal pole telefoninumbril Mobiil-ID lepingut."
        "07110066"                                | "60001019947" | false      | "Sending authentication request to phone failed" || "Kasutaja mobiiltelefoni ei saa Mobiil-ID autentimise sõnumeid saata."
        "01100266"                                | "60001019950" | false      | "User cancelled authentication"                  || "Kasutaja katkestas mobiiltelefonil Mobiil-ID autentimise."
        "00000666"                                | "60001019961" | true       | "Created signature is not valid"                 || "Autentimine Mobiil-ID-ga ei õnnestunud."
        "01200266"                                | "60001019972" | false      | "Phone cannot receive Mobile-ID auth messages"   || "Kasutaja mobiiltelefoni ei saa Mobiil-ID autentimise sõnumeid saata."
        "13100266"                                | "60001019983" | false      | "Phone is not in coverage area"                  || "Kasutaja mobiiltelefon on levialast väljas."
        "66000266"                                | "50001018908" | false      | "User timeout"                                   || "Kasutaja ei autentinud mobiiltelefonil oodatud aja jooksul. Palun proovige uuesti."
        RandomStringUtils.random(15, false, true) | "60001019939" | false      | "Telephone number length check"                  || "Kasutajal pole telefoninumbril Mobiil-ID lepingut."
    }

    @Feature("MID_AUTH_POLL_RESPONSE_COMPLETE")
    def "initialize mobile-ID authentication with scenario: #label ru"() {
        given:
        Map localeMap = ["lang": "ru"]
        Response initOIDCServiceSession = Steps.startAuthenticationInOidc(flow)
        Steps.initLoginSession(flow, initOIDCServiceSession, localeMap)
        Steps.initMidAuthSession(flow, flow.sessionId, idCode, phoneNo)

        when:
        Response response = Steps.pollMidResponse(flow, 3000L)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString("message"), startsWith(errorMessage))
        assertThat("Correct reportable value", response.jsonPath().getBoolean("reportable"), is(reportable))

        where:
        phoneNo    | idCode        | reportable | label                                            || errorMessage
        "00000266" | "60001019939" | false      | "Mobile-ID user has no active certificates"      || "У пользователя отсутствует договор об услуге"
        "07110066" | "60001019947" | false      | "Sending authentication request to phone failed" || "На телефон пользователя нельзя отправить сообщение аутентификации<span lang=\"et\"> Mobiil-ID</span>."
        "01100266" | "60001019950" | false      | "User cancelled authentication"                  || "Пользователь отменил аутентификацию с<span lang=\"et\"> Mobiil-ID </span>на своем телефоне."
        "00000666" | "60001019961" | true       | "Created signature is not valid"                 || "Аутентификация с помощью Вашего"
        "01200266" | "60001019972" | false      | "Phone cannot receive Mobile-ID auth messages"   || "На телефон пользователя нельзя отправить сообщение аутентификации<span lang=\"et\"> Mobiil-ID</span>."
        "13100266" | "60001019983" | false      | "Phone is not in coverage area"                  || "Телефон пользователя находится вне зоны доступа."
        "66000266" | "50001018908" | false      | "User timeout"                                   || "Пользователь не прошел аутентификацию на телефоне в течение требуемого времени. Пожалуйста, попробуйте еще раз."
    }

    @Feature("MID_AUTH_POLL_RESPONSE_COMPLETE")
    def "initialize mobile-ID authentication with scenario: #label en"() {
        given:
        Map localeMap = ["lang": "en"]
        Response initOIDCServiceSession = Steps.startAuthenticationInOidc(flow)
        Steps.initLoginSession(flow, initOIDCServiceSession, localeMap)
        Steps.initMidAuthSession(flow, flow.sessionId, idCode, phoneNo)

        when:
        Response response = Steps.pollMidResponse(flow, 3000L)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString("message"), startsWith(errorMessage))
        assertThat("Correct reportable value", response.jsonPath().getBoolean("reportable"), is(reportable))

        where:
        phoneNo    | idCode        | reportable | label                                            || errorMessage
        "00000266" | "60001019939" | false      | "Mobile-ID user has no active certificates"      || "User has no Mobile-ID contract with this phone number."
        "07110066" | "60001019947" | false      | "Sending authentication request to phone failed" || "User's mobile phone cannot receive Mobile-ID authentication messages."
        "01100266" | "60001019950" | false      | "User cancelled authentication"                  || "User cancelled Mobile-ID authentication on mobile phone."
        "00000666" | "60001019961" | true       | "Created signature is not valid"                 || "Authentication with Mobile-ID failed. Test your Mobile-ID with the DigiDoc4 client"
        "01200266" | "60001019972" | false      | "Phone cannot receive Mobile-ID auth messages"   || "User's mobile phone cannot receive Mobile-ID authentication messages."
        "13100266" | "60001019983" | false      | "Phone is not in coverage area"                  || "User's mobile phone is out of the coverage area."
        "66000266" | "50001018908" | false      | "User timeout"                                   || "User did not authenticate on mobile phone during the required time. Please try again."
    }

    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("MID_AUTH_PENDING")
    def "poll mobile-ID authentication session"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366")

        when:
        Response response = Requests.pollMid(flow)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct Mobile-ID status", response.jsonPath().getString("status"), is("PENDING"))
    }

    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("MID_AUTH_SUCCESS")
    def "poll mobile-ID authentication with session complete"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366")
        sleep 10000

        when:
        Response response = Requests.pollMid(flow)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct Mobile-ID status", response.jsonPath().getString("status"), is("COMPLETED"))
    }

    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    def "poll mobile-ID authentication session with invalid session ID"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366")
        flow.setSessionId("1234567")

        when:
        Response response = Requests.pollMid(flow)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct Mobile-ID status", response.jsonPath().getString("message"), is(MESSAGE_SESSION_NOT_FOUND))
    }

    //TODO: AUT-630
    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    def "poll mobile-ID authentication with invalid method post"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366")

        when:
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullMidPollUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString("message"), is(MESSAGE_INTERNAL_ERROR))
    }

    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("MID_AUTH_CANCELED")
    def "cancel mobile-ID authentication"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366")

        when:
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullMidCancelUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(302))
        assertThat("Correct location header", response.header("location"), is(flow.loginService.initUrl + "?login_challenge=" + flow.loginChallenge))
    }

    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Verify cancel mobile-ID authentication response headers"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366")

        when:
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullMidCancelUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(302))
        Steps.verifyResponseHeaders(response)
    }

    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    def "cancel mobile-ID authentication with invalid session ID"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366")
        flow.setSessionId("1234567")

        when:
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullMidCancelUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(403))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_FORBIDDEN))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_FORBIDDEN_REQUEST))
    }

    //TODO: AUT-630
    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    def "cancel mobile-ID authentication with invalid method get"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366")

        when:
        Response response = Requests.getRequestWithSessionId(flow, flow.loginService.fullMidCancelUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_INTERNAL))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_INTERNAL_ERROR))
    }
}
