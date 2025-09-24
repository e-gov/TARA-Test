package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import ee.ria.tara.model.ErrorMessage
import ee.ria.tara.util.ErrorValidator
import io.qameta.allure.Feature
import io.qameta.allure.Issue
import io.restassured.filter.cookie.CookieFilter
import io.restassured.http.Method
import io.restassured.response.Response
import org.apache.http.HttpStatus

import static io.restassured.RestAssured.given
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.greaterThan
import static org.hamcrest.Matchers.is

class SmartIDAuthSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Feature("SID_AUTH_SPECIAL_ACCOUNTS")
    def "Authenticate with Smart-id account: #label"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Response sidAuthResponse = Steps.authenticateWithSid(flow, idCode)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, sidAuthResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience[0], is(ClientStore.mockPublic.clientId))
        assertThat("Correct subject", claims.subject, is("EE" + idCode))
        assertThat("Correct given name", claims.getJSONObjectClaim("profile_attributes")["given_name"], is(givenName))
        assertThat("Correct family game", claims.getJSONObjectClaim("profile_attributes")["family_name"], is(familyName))
        assertThat("Correct date of birth", claims.getJSONObjectClaim("profile_attributes")["date_of_birth"], is(dateOfBirth))

        where:
        idCode        || givenName      | familyName   | dateOfBirth  | label
        "61101012257" || "OK"           | "TESTMINOR"  | "2011-01-01" | "User age is under 18"
//Smart-ID number 30303039903 is not marked in SK smart-id-documentation https://github.com/SK-EID/smart-id-documentation/wiki/Environment-technical-parameters#test-accounts-for-automated-testing
        "30303039903" || "OK"           | "TEST"       | "1903-03-03" | "No numbers in names"
        "39901012239" || "OK"           | "TEST"       | "1999-01-01" | "User has other active account"
    }

    @Feature("SID_AUTH_INIT_ENDPOINT")
    def "Initialize Smart-ID authentication"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid")

        when:
        Response response = Steps.initSidAuthSession(flow, "40404049996")

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        assertThat("Correct Content-Type", response.contentType, is("text/html;charset=UTF-8"))
        String controlCode = response.htmlPath().getString("**.find { p -> p.@class == 'control-code' }.text()")
        assertThat("Verification code exists", controlCode.size(), is(4))
    }

    @Feature("SID_AUTH_INIT_ENDPOINT")
    def "Initialize Smart-ID authentication with invalid session cookie: #reason"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")

        when: "initialize Smart-ID authentication with invalid session cookie"
        Response response = given()
                .params([idCode: "40404049996",
                         _csrf : flow.csrf])
                .cookies(cookie)
                .post(flow.loginService.fullSidInitUrl)

        then:
        ErrorValidator.validate(response, ErrorMessage.INVALID_CSRF_TOKEN)

        where:
        cookie                        | reason
        [:]                           | "no cookie"
        ["__Host-SESSION": null]      | "empty cookie"
        ["__Host-SESSION": "1234567"] | "incorrect cookie value"
    }

    @Issue("AUT-630")
    @Feature("SID_AUTH_INIT_ENDPOINT")
    def "Initialize Smart-ID authentication with invalid method: #requestType"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")

        when: "initialize Smart-ID authentication with invalid method"
        Response response = given()
                .params([idCode: "40404049996",
                         _csrf : flow.csrf])
                .cookies(["__Host-SESSION": flow.sessionId])
                .request(requestType, flow.loginService.fullSidInitUrl)
        then:
        ErrorValidator.validate(response, ErrorMessage.INTERNAL_ERROR)

        where:
        requestType   | _
        Method.GET    | _
        Method.PUT    | _
        Method.PATCH  | _
        Method.DELETE | _
    }

    @Feature("SID_AUTH_INIT_ENDPOINT")
    @Feature("SID_AUTH_CHECKS_IDCODE")
    def "Initialize Smart-ID authentication with invalid params: #label"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")

        when:
        Response response = given()
                .params(_csrf: flow.csrf)
                .params(params)
                .cookies("__Host-SESSION": flow.sessionId)
                .post(flow.loginService.fullSidInitUrl)

        then:
        ErrorValidator.validate(response, errorMessage)

        where:
        params                                                                 | label                        || errorMessage
        [idCode: "60001019938"]                                                | "invalid idCode checksum"    || ErrorMessage.MID_INVALID_IDENTITY_CODE
        [:]                                                                    | "missing idCode"             || ErrorMessage.MID_INVALID_IDENTITY_CODE
        [idCode: "600010199399"]                                               | "too long idCode"            || ErrorMessage.MID_INVALID_IDENTITY_CODE
        [idCode: "60001329939"]                                                | "wrong date inside idCode"   || ErrorMessage.MID_INVALID_IDENTITY_CODE
        [idCode: "6000"]                                                       | "too short idCode"           || ErrorMessage.MID_INVALID_IDENTITY_CODE
        [idCode: "38500030556"]                                                | "invalid month in idCode"    || ErrorMessage.MID_INVALID_IDENTITY_CODE
        [idCode: ["60001017716", "60001017727"]]                               | "multiple idCode parameters" || ErrorMessage.DUPLICATE_PARAMETERS
        [idCode: "60001017716", _csrf: "d7860443-a0cc-45db-ad68-3c9300c0b3bb"] | "multiple _csrf parameters"  || ErrorMessage.DUPLICATE_PARAMETERS
    }

    @Feature("SID_AUTH_INIT_ENDPOINT")
    def "Initialize Smart-ID authentication with no smart-id contract: #label"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid", login_locale)
        Steps.initSidAuthSession(flow, "29101290233")

        when:
        Response pollResponse = Steps.pollSidResponse(flow, 1000L)

        then:
        ErrorValidator.validate(pollResponse, HttpStatus.SC_BAD_REQUEST, errorMessage)
        pollResponse.then().body("incident_nr.size()", greaterThan(15))

        where:
        login_locale | label             || errorMessage
        "et"         | "Estonian locale" || ErrorMessage.SID_ACCOUNT_NOT_FOUND.message
        "en"         | "English locale"  || "User has no<span translate=\"no\" lang=\"en\"> Smart-ID </span>account."
        "ru"         | "Russian locale"  || "У пользователя нет учетной записи<span translate=\"no\" lang=\"en\"> Smart-ID</span>."
    }

    @Feature("SID_AUTH_POLL_RESPONSE_COMPLETED_ERRORS")
    def "Initialize Smart-ID authentication with scenario: #label et"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid", "et")
        Steps.initSidAuthSession(flow, idCode)

        when:
        Response pollResponse = Steps.pollSidResponse(flow, 3000L)

        then:
        ErrorValidator.validate(pollResponse, HttpStatus.SC_BAD_REQUEST, errorMessage)
        pollResponse.then().body("reportable", is(false))

        where:
        idCode        | label                                             || errorMessage
        "30403039917" | "USER_REFUSED"                                    || "Kasutaja katkestas autentimise<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses."
        "30403039928" | "USER_REFUSED_DISPLAYTEXTANDPIN"                  || "Kasutaja katkestas<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses PIN koodi sisestamise."
        "30403039939" | "USER_REFUSED_VC_CHOICE"                          || "Kasutaja katkestas<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses kontrollkoodi valiku."
        "30403039946" | "USER_REFUSED_CONFIRMATIONMESSAGE"                || "Kasutaja katkestas autentimise<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses kinnitusekraanil."
        "30403039950" | "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE" || "Kasutaja katkestas autentimise<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses kontrollkoodi kinnituskraanil."
        "30403039972" | "WRONG_VC"                                        || "Kasutaja valis<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses vale kontrollkoodi."
    }

    @Feature("SID_AUTH_POLL_RESPONSE_COMPLETED_ERRORS")
    def "Initialize Smart-ID authentication with scenario: #label en"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid", "en")
        Steps.initSidAuthSession(flow, idCode)

        when:
        Response pollResponse = Steps.pollSidResponse(flow, 3000L)

        then:
        ErrorValidator.validate(pollResponse, HttpStatus.SC_BAD_REQUEST, errorMessage)
        pollResponse.then().body("reportable", is(false))

        where:
        idCode        | label                                             || errorMessage
        "30403039917" | "USER_REFUSED"                                    || "User cancelled authentication in the<span translate=\"no\" lang=\"en\"> Smart-ID </span>app."
        "30403039928" | "USER_REFUSED_DISPLAYTEXTANDPIN"                  || "User cancelled PIN code entry in the<span translate=\"no\" lang=\"en\"> Smart-ID </span>app."
        "30403039939" | "USER_REFUSED_VC_CHOICE"                          || "User cancelled verification code choice in the<span translate=\"no\" lang=\"en\"> Smart-ID </span>app."
        "30403039946" | "USER_REFUSED_CONFIRMATIONMESSAGE"                || "User cancelled authentication on the confirmation screen in the<span translate=\"no\" lang=\"en\"> Smart-ID </span>app."
        "30403039950" | "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE" || "User cancelled authentication on the verification code choice confirmation screen in the<span translate=\"no\" lang=\"en\"> Smart-ID </span>app."
        "30403039972" | "WRONG_VC"                                        || "User chose the wrong verification code in the<span translate=\"no\" lang=\"en\"> Smart-ID </span>app."
    }

    @Feature("SID_AUTH_POLL_RESPONSE_COMPLETED_ERRORS")
    def "Initialize Smart-ID authentication with scenario: #label ru"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid", "ru")
        Steps.initSidAuthSession(flow, idCode)

        when:
        Response pollResponse = Steps.pollSidResponse(flow, 3000L)

        then:
        ErrorValidator.validate(pollResponse, HttpStatus.SC_BAD_REQUEST, errorMessage)
        pollResponse.then().body("reportable", is(false))

        where:
        idCode        | label                                             || errorMessage
        "30403039917" | "USER_REFUSED"                                    || "Пользователь прервал аутентификацию в приложении<span translate=\"no\" lang=\"en\"> Smart-ID</span>."
        "30403039928" | "USER_REFUSED_DISPLAYTEXTANDPIN"                  || "Пользователь отменил ввод PIN-кода в приложении<span translate=\"no\" lang=\"en\"> Smart-ID</span>."
        "30403039939" | "USER_REFUSED_VC_CHOICE"                          || "Пользователь отменил выбор кода подтверждения в приложении<span translate=\"no\" lang=\"en\"> Smart-ID</span>."
        "30403039946" | "USER_REFUSED_CONFIRMATIONMESSAGE"                || "Пользователь отменил аутентификацию на экране подтверждения в приложении<span translate=\"no\" lang=\"en\"> Smart-ID</span>."
        "30403039950" | "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE" || "Пользователь отменил аутентификацию на экране подтверждения контрольного кода в приложении<span translate=\"no\" lang=\"en\"> Smart-ID</span>."
        "30403039972" | "WRONG_VC"                                        || "Пользователь выбрал неправильный код подтверждения в приложении<span translate=\"no\" lang=\"en\"> Smart-ID</span>."
    }

    @Feature("SID_AUTH_POLL_RESPONSE_TIMEOUT_ERROR")
    def "Initialize Smart-ID authentication with scenario: TIMEOUT #login_locale"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid", login_locale)
        Steps.initSidAuthSession(flow, "30403039983")

        when:
        Response pollResponse = Steps.pollSidResponse(flow, 10000L)

        then:
        ErrorValidator.validate(pollResponse, HttpStatus.SC_BAD_REQUEST, errorMessage)
        pollResponse.then().body("reportable", is(false))

        where:
        login_locale || errorMessage
        "et"         || ErrorMessage.SID_SESSION_TIMED_OUT.message
        "en"         || "User did not authenticate in the<span translate=\"no\" lang=\"en\"> Smart-ID </span>app within the required time. Please try again."
        "ru"         || "Пользователь не прошел аутентификацию в приложении<span translate=\"no\" lang=\"en\"> Smart-ID </span>в течение требуемого времени. Пожалуйста, попробуйте еще раз."
    }

    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("SID_AUTH_PENDING")
    def "Poll Smart-ID authentication session"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Steps.initSidAuthSession(flow, "30403039983")

        when:
        Response response = Requests.pollSid(flow)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct Mobile-ID status", response.jsonPath().getString("status"), is("PENDING"))
    }

    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("SID_AUTH_SUCCESS")
    def "Poll Smart-ID authentication with session complete"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Steps.initSidAuthSession(flow, "40404049996")

        when:
        Response response = Steps.pollSidResponse(flow)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct Mobile-ID status", response.jsonPath().getString("status"), is("COMPLETED"))
    }

    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    def "Poll Smart-ID authentication session with invalid session cookie: #reason"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Steps.initSidAuthSession(flow, "30403039983")

        when: "request polling with invalid session cookie"
        Response response = given()
                .cookies(cookie)
                .get(flow.loginService.fullSidPollUrl)
        then:
        ErrorValidator.validate(response, ErrorMessage.SESSION_NOT_FOUND)

        where:
        cookie                        | reason
        [:]                           | "no cookie"
        ["__Host-SESSION": null]      | "empty cookie"
        ["__Host-SESSION": "1234567"] | "incorrect cookie value"
    }

    @Issue("AUT-630")
    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    def "Poll Smart-ID authentication with invalid method: #requestType"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Steps.initSidAuthSession(flow, "40404049996")

        when: "request Smart-ID polling with invalid request type"
        Response response = given()
                .cookies("__Host-SESSION": flow.sessionId)
                .params([_csrf: flow.csrf])
                .request(requestType, flow.loginService.fullSidPollUrl)

        then:
        ErrorValidator.validate(response, ErrorMessage.INTERNAL_ERROR)

        where:
        requestType   | _
        Method.POST   | _
        Method.PUT    | _
        Method.PATCH  | _
        Method.DELETE | _
    }

    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("SID_AUTH_CANCELED")
    def "Cancel Smart-ID authentication"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Steps.initSidAuthSession(flow, "40404049996")

        when:
        Response response = Requests.postRequest(flow, flow.loginService.fullSidCancelUrl)

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
    def "Verify cancel Smart-ID authentication response headers"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Steps.initSidAuthSession(flow, "40404049996")

        when:
        Response response = Requests.postRequest(flow, flow.loginService.fullSidCancelUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(302))
        Steps.verifyResponseHeaders(response)
    }

    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    def "Cancel Smart-ID authentication with invalid session cookie: #reason"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Steps.initSidAuthSession(flow, "40404049996")

        when: "Cancel Smart-ID authentication with invalid session cookie"
        Response response = given()
                .cookies(cookie)
                .post(flow.loginService.fullSidCancelUrl)

        then:
        ErrorValidator.validate(response, ErrorMessage.INVALID_CSRF_TOKEN)

        where:
        cookie                        | reason
        [:]                           | "no cookie"
        ["__Host-SESSION": null]      | "empty cookie"
        ["__Host-SESSION": "1234567"] | "incorrect cookie value"
    }

    @Issue("AUT-630")
    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    def "Cancel Smart-ID authentication with invalid method #requestType"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Steps.initSidAuthSession(flow, "40404049996")

        when: "Cancel authentication with invalid method"
        Response response = given()
                .params([_csrf: flow.csrf])
                .cookies(["__Host-SESSION": flow.sessionId])
                .request(requestType, flow.loginService.fullSidCancelUrl)

        then:
        ErrorValidator.validate(response, ErrorMessage.INTERNAL_ERROR)

        where:
        requestType   | _
        Method.GET    | _
        Method.PUT    | _
        Method.PATCH  | _
        Method.DELETE | _
    }
}
