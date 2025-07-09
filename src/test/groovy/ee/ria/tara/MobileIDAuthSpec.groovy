package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.commons.lang3.RandomStringUtils

import static io.restassured.RestAssured.given
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.startsWith

class MobileIDAuthSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Feature("MID_INIT_ENDPOINT")
    def "Initialize mobile-ID authentication"() {
        given:
        Steps.startAuthenticationInTara(flow)

        when:
        Response response = Steps.initMidAuthSession(flow, "60001017716", "69100366")

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        assertThat("Correct Content-Type", response.contentType, is("text/html;charset=UTF-8"))
        String controlCode = response.htmlPath().getString("**.find { p -> p.@class == 'control-code' }.text()")
        assertThat("Verification code exists", controlCode.size(), is(4))
    }

    @Feature("MID_INIT_ENDPOINT")
    def "Initialize Mobile-ID authentication with invalid session cookie: #reason"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")

        when: "initialize Mobile-ID authentication with invalid session cookie"
        Response response = given()
                .params([idCode: "40404049996",
                         _csrf : flow.csrf])
                .cookies(cookie)
                .post(flow.loginService.fullMidInitUrl)

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

    //TODO: AUT-630
    @Feature("MID_INIT_ENDPOINT")
    def "Initialize mobile-ID authentication with invalid method: #requestType"() {
        given:
        Steps.startAuthenticationInTara(flow)

        when: "initialize mobile-ID authentication with invalid method"
        Response response = given()
                .params([idCode         : "60001017716",
                         telephoneNumber: "69100366",
                         _csrf          : flow.csrf])
                .cookies(["__Host-SESSION": flow.sessionId])
                .request(requestType, flow.loginService.fullMidInitUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_INTERNAL))
        assertThat("Correct message", response.jsonPath().getString('message'), is(MESSAGE_INTERNAL_ERROR))

        where:
        requestType | _
        "GET"       | _
        "PUT"       | _
        "PATCH"     | _
        "DELETE"    | _
    }

    @Feature("MID_INIT_ENDPOINT")
    @Feature("MID_VALID_INPUT_IDCODE")
    @Feature("MID_VALID_INPUT_TEL")
    def "Initialize mobile-ID authentication with invalid params: #label"() {
        given:
        Steps.startAuthenticationInTara(flow)

        when: "Request MID authentication with invalid parameters"
        Response response = given()
                .params(params)
                .params(_csrf: flow.csrf)
                .cookies(["__Host-SESSION": flow.sessionId])
                .post(flow.loginService.fullMidInitUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString("message"), is(errorMessage))

        where:
        params                                                                              | label                                 || errorMessage
        [telephoneNumber: "00000266", idCode: "60001019938"]                                | "invalid idCode checksum"             || MESSAGE_INCORRECT_ID_CODE
        [telephoneNumber: "+37200000266", idCode: "60001019939"]                            | "invalid telephone number"            || "Telefoninumber ei ole korrektne."
        [:]                                                                                 | "missing telephone number and idCode" || MESSAGE_INCORRECT_ID_CODE + "; Telefoninumber ei ole korrektne."
        [telephoneNumber: "00000266"]                                                       | "missing idCode"                      || MESSAGE_INCORRECT_ID_CODE
        [idCode: "60001019939"]                                                             | "missing telephone number"            || "Telefoninumber ei ole korrektne."
        [telephoneNumber: "00000266", idCode: "600010199399"]                               | "too long idCode"                     || MESSAGE_INCORRECT_ID_CODE
        [telephoneNumber: "00000266", idCode: "60001329939"]                                | "wrong date inside idCode"            || MESSAGE_INCORRECT_ID_CODE
        [telephoneNumber: "00000266", idCode: "6000"]                                       | "too short idCode"                    || MESSAGE_INCORRECT_ID_CODE
        [telephoneNumber: "abcd", idCode: "ABCD"]                                           | "invalid telephone number and idCode" || MESSAGE_INCORRECT_ID_CODE + "; Telefoninumber ei ole korrektne."
        [telephoneNumber: "00000266", idCode: "38500030556"]                                | "invalid month in idCode"             || MESSAGE_INCORRECT_ID_CODE
        [telephoneNumber: "45", idCode: "60001019939"]                                      | "too short telephone number"          || "Telefoninumber ei ole korrektne."
        [telephoneNumber: RandomStringUtils.random(16, false, true), idCode: "60001019939"] | "too long telephone number"           || "Telefoninumber ei ole korrektne."
        [telephoneNumber: "69100366", idCode: ["60001017716", "60001017727"]]               | "multiple idCode parameters"          || MESSAGE_DUPLICATE_PARAMETERS
        [telephoneNumber: ["69100366", "00000766"], idCode: "60001017716"]                  | "multiple telephoneNumber parameters" || MESSAGE_DUPLICATE_PARAMETERS
    }

    @Feature("MID_AUTH_POLL_RESPONSE_COMPLETE")
    @Feature("MID_VALID_INPUT_TEL")
    @Feature("MID_AUTH_FAILED")
    def "Initialize mobile-ID authentication with scenario: #label et"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, idCode, phoneNo)

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
    def "Initialize mobile-ID authentication with scenario: #label ru"() {
        given:
        Map localeMap = ["lang": "ru"]
        Response initOIDCServiceSession = Steps.startAuthenticationInOidc(flow)
        Steps.initLoginSession(flow, initOIDCServiceSession, localeMap)
        Steps.initMidAuthSession(flow, idCode, phoneNo)

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
    def "Initialize mobile-ID authentication with scenario: #label en"() {
        given:
        Map localeMap = ["lang": "en"]
        Response initOIDCServiceSession = Steps.startAuthenticationInOidc(flow)
        Steps.initLoginSession(flow, initOIDCServiceSession, localeMap)
        Steps.initMidAuthSession(flow, idCode, phoneNo)

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
    def "Poll mobile-ID authentication session"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, "60001017716", "69100366")

        when:
        Response response = Requests.pollMid(flow)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct Mobile-ID status", response.jsonPath().getString("status"), is("PENDING"))
    }

    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("MID_AUTH_SUCCESS")
    def "Poll mobile-ID authentication with session complete"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, "60001017716", "69100366")
        sleep 10000

        when:
        Response response = Requests.pollMid(flow)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct Mobile-ID status", response.jsonPath().getString("status"), is("COMPLETED"))
    }

    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    def "Poll mobile-ID authentication session with invalid session cookie: #reason"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, "60001017716", "69100366")

        when: "request polling with invalid session cookie"
        Response response = given()
                .cookies(cookie)
                .get(flow.loginService.fullMidPollUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct Mobile-ID status", response.jsonPath().getString("message"), is(MESSAGE_SESSION_NOT_FOUND))

        where:
        cookie                        | reason
        [:]                           | "no cookie"
        ["__Host-SESSION": null]      | "empty cookie"
        ["__Host-SESSION": "1234567"] | "incorrect cookie value"
    }

    //TODO: AUT-630
    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    def "Poll mobile-ID authentication with invalid method: #requestType"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, "60001017716", "69100366")

        when: "request MID polling with invalid request type"
        Response response = given()
                .cookies("__Host-SESSION": flow.sessionId)
                .params([_csrf: flow.csrf])
                .request(requestType, flow.loginService.fullMidPollUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString("message"), is(MESSAGE_INTERNAL_ERROR))

        where:
        requestType | _
        "POST"      | _
        "PUT"       | _
        "PATCH"     | _
        "DELETE"    | _
    }

    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("MID_AUTH_CANCELED")
    def "Cancel mobile-ID authentication"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, "60001017716", "69100366")

        when:
        Response response = Requests.postRequest(flow, flow.loginService.fullMidCancelUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(302))
        assertThat("Correct location header", response.header("location"), is(flow.loginService.initUrl + "?login_challenge=" + flow.loginChallenge + "&lang=et"))
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
        Steps.initMidAuthSession(flow, "60001017716", "69100366")

        when:
        Response response = Requests.postRequest(flow, flow.loginService.fullMidCancelUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(302))
        Steps.verifyResponseHeaders(response)
    }

    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    def "Cancel mobile-ID authentication with invalid session cookie: #reason"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, "60001017716", "69100366")

        when: "Cancel MID authentication with invalid session cookie"
        Response response = given()
                .cookies(cookie)
                .post(flow.loginService.fullMidCancelUrl)

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

    //TODO: AUT-630
    @Feature("MID_AUTH_STATUS_CHECK_ENDPOINT")
    def "Cancel mobile-ID authentication with invalid method get"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Steps.initMidAuthSession(flow, "60001017716", "69100366")

        when: "Cancel authentication with invalid method"
        Response response = given()
                .params([_csrf: flow.csrf])
                .cookies(["__Host-SESSION": flow.sessionId])
                .request(requestType, flow.loginService.fullMidCancelUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_INTERNAL))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_INTERNAL_ERROR))

        where:
        requestType | _
        "GET"       | _
        "PUT"       | _
        "PATCH"     | _
        "DELETE"    | _
    }
}
