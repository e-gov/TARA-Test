package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static io.restassured.RestAssured.given
import static org.hamcrest.Matchers.greaterThan
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.MatcherAssert.assertThat

class SmartIDAuthSpec extends TaraSpecification {
    Flow flow = new Flow(props)

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
        assertThat("Correct audience", claims.audience[0], is(flow.oidcClientPublic.clientId))
        assertThat("Correct subject", claims.subject, is("EE" + idCode))
        assertThat("Correct given name", claims.getJSONObjectClaim("profile_attributes")["given_name"], is(givenName))
        assertThat("Correct family game", claims.getJSONObjectClaim("profile_attributes")["family_name"], is(familyName))
        assertThat("Correct date of birth", claims.getJSONObjectClaim("profile_attributes")["date_of_birth"], is(dateOfBirth))

        where:
        idCode        || givenName      | familyName   | dateOfBirth  | label
        "50701019992" || "MINOR"        | "TESTNUMBER" | "2007-01-01" | "User age is under 18"
        "30303039903" || "QUALIFIED OK" | "TESTNUMBER" | "1903-03-03" | "No numbers in names"
        "30303039816" || "MULTIPLE OK"  | "TESTNUMBER" | "1903-03-03" | "User has other active account"
    }

    @Feature("SID_AUTH_INIT_ENDPOINT")
    def "Initialize Smart-ID authentication"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid")

        when:
        Response response = Steps.initSidAuthSession(flow, "30303039914")

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
                .relaxedHTTPSValidation()
                .params([idCode: "30303039914",
                         _csrf : flow.csrf])
                .cookies(cookie)
                .post(flow.loginService.fullSidInitUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(403))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_FORBIDDEN))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_FORBIDDEN_REQUEST))

        where:
        cookie                        | reason
        [:]                           | "no cookie"
        ["__Host-SESSION": null]      | "empty cookie"
        ["__Host-SESSION": "1234567"] | "incorrect cookie value"
    }

    //TODO: AUT-630
    @Feature("SID_AUTH_INIT_ENDPOINT")
    def "Initialize Smart-ID authentication with invalid method: #requestType"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")

        when: "initialize Smart-ID authentication with invalid method"
        Response response = given()
                .relaxedHTTPSValidation()
                .params([idCode: "30303039914",
                         _csrf : flow.csrf])
                .cookies(["__Host-SESSION": flow.sessionId])
                .request(requestType, flow.loginService.fullSidInitUrl)
        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_INTERNAL))
        assertThat("Correct error message", response.jsonPath().getString("message"), is(MESSAGE_INTERNAL_ERROR))

        where:
        requestType | _
        "GET"       | _
        "PUT"       | _
        "PATCH"     | _
        "DELETE"    | _
    }

    @Feature("SID_AUTH_INIT_ENDPOINT")
    @Feature("SID_AUTH_CHECKS_IDCODE")
    def "Initialize Smart-ID authentication with invalid params: #label"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")

        when:
        Response response = given()
                .relaxedHTTPSValidation()
                .params(_csrf: flow.csrf)
                .params(params)
                .cookies("__Host-SESSION": flow.sessionId)
                .post(flow.loginService.fullSidInitUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", response.jsonPath().getString("message"), is(errorMessage))

        where:
        params                                                                 | label                        || errorMessage
        [idCode: "60001019938"]                                                | "invalid idCode checksum"    || "Isikukood ei ole korrektne."
        [:]                                                                    | "missing idCode"             || "Isikukood ei ole korrektne."
        [idCode: "600010199399"]                                               | "too long idCode"            || "Isikukood ei ole korrektne."
        [idCode: "60001329939"]                                                | "wrong date inside idCode"   || "Isikukood ei ole korrektne."
        [idCode: "6000"]                                                       | "too short idCode"           || "Isikukood ei ole korrektne."
        [idCode: "38500030556"]                                                | "invalid month in idCode"    || "Isikukood ei ole korrektne."
        [idCode: ["60001017716", "60001017727"]]                               | "multiple idCode parameters" || MESSAGE_DUPLICATE_PARAMETERS
        [idCode: "60001017716", _csrf: "d7860443-a0cc-45db-ad68-3c9300c0b3bb"] | "multiple _csrf parameters"  || MESSAGE_DUPLICATE_PARAMETERS
    }

    @Feature("SID_AUTH_INIT_ENDPOINT")
    def "Initialize Smart-ID authentication with no smart-id contract: #label"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid", login_locale)
        Steps.initSidAuthSession(flow, "29101290233")

        when:
        Response pollResponse = Steps.pollSidResponse(flow, 1000L)

        then:
        assertThat("Correct HTTP status code", pollResponse.statusCode, is(400))
        assertThat("Correct Content-Type", pollResponse.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", pollResponse.jsonPath().getString("message"), containsString(errorMessage))
        assertThat("Incident number is present", pollResponse.jsonPath().getString("incident_nr").size(), greaterThan(15))

        where:
        login_locale | label             || errorMessage
        "et"         | "Estonian locale" || "Kasutajal puudub"
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
        assertThat("Correct HTTP status code", pollResponse.statusCode, is(400))
        assertThat("Correct Content-Type", pollResponse.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", pollResponse.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", pollResponse.jsonPath().getString("message"), is(errorMessage))
        assertThat("Error not reportable", pollResponse.jsonPath().getBoolean("reportable"), is(false))

        where:
        idCode        | label                                             || errorMessage
        "30403039917" | "USER_REFUSED"                                    || "Kasutaja katkestas autentimise<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses."
        "30403039928" | "USER_REFUSED_DISPLAYTEXTANDPIN"                  || "Kasutaja katkestas<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses PIN koodi sisestamise."
        "30403039939" | "USER_REFUSED_VC_CHOICE"                          || "Kasutaja katkestas<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses kontrollkoodi valiku."
        "30403039946" | "USER_REFUSED_CONFIRMATIONMESSAGE"                || "Kasutaja katkestas autentimise<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses kinnitusekraanil."
        "30403039950" | "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE" || "Kasutaja katkestas autentimise<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses kontrollkoodi kinnituskraanil."
        "30403039961" | "USER_REFUSED_CERT_CHOICE"                        || "Kasutajal on mitu<span translate=\"no\" lang=\"en\"> Smart-ID </span>kontot ja ühe kontoga tühistati autentimine."
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
        assertThat("Correct HTTP status code", pollResponse.statusCode, is(400))
        assertThat("Correct Content-Type", pollResponse.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", pollResponse.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", pollResponse.jsonPath().getString("message"), is(errorMessage))
        assertThat("Error not reportable", pollResponse.jsonPath().getBoolean("reportable"), is(false))

        where:
        idCode        | label                                             || errorMessage
        "30403039917" | "USER_REFUSED"                                    || "User cancelled authentication in the<span translate=\"no\" lang=\"en\"> Smart-ID </span>app."
        "30403039928" | "USER_REFUSED_DISPLAYTEXTANDPIN"                  || "User cancelled PIN code entry in the<span translate=\"no\" lang=\"en\"> Smart-ID </span>app."
        "30403039939" | "USER_REFUSED_VC_CHOICE"                          || "User cancelled verification code choice in the<span translate=\"no\" lang=\"en\"> Smart-ID </span>app."
        "30403039946" | "USER_REFUSED_CONFIRMATIONMESSAGE"                || "User cancelled authentication on the confirmation screen in the<span translate=\"no\" lang=\"en\"> Smart-ID </span>app."
        "30403039950" | "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE" || "User cancelled authentication on the verification code choice confirmation screen in the<span translate=\"no\" lang=\"en\"> Smart-ID </span>app."
        "30403039961" | "USER_REFUSED_CERT_CHOICE"                        || "User has multiple<span translate=\"no\" lang=\"en\"> Smart-ID </span>accounts and one of them has cancelled authentication."
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
        assertThat("Correct HTTP status code", pollResponse.statusCode, is(400))
        assertThat("Correct Content-Type", pollResponse.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", pollResponse.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", pollResponse.jsonPath().getString("message"), is(errorMessage))
        assertThat("Error not reportable", pollResponse.jsonPath().getBoolean("reportable"), is(false))

        where:
        idCode        | label                                             || errorMessage
        "30403039917" | "USER_REFUSED"                                    || "Пользователь прервал аутентификацию в приложении<span translate=\"no\" lang=\"en\"> Smart-ID</span>."
        "30403039928" | "USER_REFUSED_DISPLAYTEXTANDPIN"                  || "Пользователь отменил ввод PIN-кода в приложении<span translate=\"no\" lang=\"en\"> Smart-ID</span>."
        "30403039939" | "USER_REFUSED_VC_CHOICE"                          || "Пользователь отменил выбор кода подтверждения в приложении<span translate=\"no\" lang=\"en\"> Smart-ID</span>."
        "30403039946" | "USER_REFUSED_CONFIRMATIONMESSAGE"                || "Пользователь отменил аутентификацию на экране подтверждения в приложении<span translate=\"no\" lang=\"en\"> Smart-ID</span>."
        "30403039950" | "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE" || "Пользователь отменил аутентификацию на экране подтверждения контрольного кода в приложении<span translate=\"no\" lang=\"en\"> Smart-ID</span>."
        "30403039961" | "USER_REFUSED_CERT_CHOICE"                        || "У пользователя несколько учетных записей<span translate=\"no\" lang=\"en\"> Smart-ID</span>, и одна из них отменила аутентификацию."
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
        assertThat("Correct HTTP status code", pollResponse.statusCode, is(400))
        assertThat("Correct Content-Type", pollResponse.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", pollResponse.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", pollResponse.jsonPath().getString("message"), is(errorMessage))
        assertThat("Error not reportable", pollResponse.jsonPath().getBoolean("reportable"), is(false))

        where:
        login_locale || errorMessage
        "et"         || "Kasutaja ei autentinud<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses oodatud aja jooksul. Palun proovige uuesti."
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
        Steps.initSidAuthSession(flow, "30303039914")

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
                .relaxedHTTPSValidation()
                .cookies(cookie)
                .get(flow.loginService.fullSidPollUrl)
        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_SESSION_NOT_FOUND))

        where:
        cookie                        | reason
        [:]                           | "no cookie"
        ["__Host-SESSION": null]      | "empty cookie"
        ["__Host-SESSION": "1234567"] | "incorrect cookie value"
    }

    //TODO: AUT-630
    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    def "Poll Smart-ID authentication with invalid method: #requestType"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Steps.initSidAuthSession(flow, "30303039914")

        when: "request Smart-ID polling with invalid request type"
        Response response = given()
                .relaxedHTTPSValidation()
                .cookies("__Host-SESSION": flow.sessionId)
                .params([_csrf: flow.csrf])
                .request(requestType, flow.loginService.fullSidPollUrl)

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

    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("SID_AUTH_CANCELED")
    def "Cancel Smart-ID authentication"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Steps.initSidAuthSession(flow, "30303039914")

        when:
        Response response = Requests.postRequest(flow, flow.loginService.fullSidCancelUrl)

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
    def "Verify cancel Smart-ID authentication response headers"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Steps.initSidAuthSession(flow, "30303039914")

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
        Steps.initSidAuthSession(flow, "30303039914")

        when: "Cancel Smart-ID authentication with invalid session cookie"
        Response response = given()
                .relaxedHTTPSValidation()
                .cookies(cookie)
                .post(flow.loginService.fullSidCancelUrl)

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
    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    def "Cancel Smart-ID authentication with invalid method #requestType"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Steps.initSidAuthSession(flow, "30303039914")

        when: "Cancel authentication with invalid method"
        Response response = given()
                .relaxedHTTPSValidation()
                .params([_csrf: flow.csrf])
                .cookies(["__Host-SESSION": flow.sessionId])
                .request(requestType, flow.loginService.fullSidCancelUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
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
