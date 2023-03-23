package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Unroll

import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.startsWith
import static org.junit.jupiter.api.Assertions.*
import static org.hamcrest.MatcherAssert.assertThat

class SmartIDAuthSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Unroll
    @Feature("SID_AUTH_SPECIAL_ACCOUNTS")
    def "Authenticate with Smart-id account: #label"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Response sidAuthResponse = Steps.authenticateWithSid(flow, idCode)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, sidAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClientPublic.clientId))
        assertThat(claims.getSubject(), equalTo("EE" + idCode))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo(givenName))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("family_name"), equalTo(familyName))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("date_of_birth"), equalTo(dateOfBirth))

        where:
        idCode        | givenName      | familyName   | dateOfBirth  | label
        "50701019992" | "MINOR"        | "TESTNUMBER" | "2007-01-01" | "User age is under 18"
        "30303039903" | "QUALIFIED OK" | "TESTNUMBER" | "1903-03-03" | "No numbers in names"
        "30303039816" | "MULTIPLE OK"  | "TESTNUMBER" | "1903-03-03" | "User has other active account"
    }

    @Unroll
    @Feature("SID_AUTH_INIT_ENDPOINT")
    def "initialize Smart-ID authentication"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, "30303039914", additionalParamsMap)
        assertEquals(200, initSidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", initSidAuthenticationSession.getContentType(), "Correct Content-Type is returned")
        String controlCode = initSidAuthenticationSession.body().htmlPath().getString("**.find { p -> p.@class == 'control-code' }.text()")
        assertEquals(4, controlCode.size(), "Verification code exists")
    }

    //TODO: AUT-630
    @Unroll
    @Feature("SID_AUTH_INIT_ENDPOINT")
    def "initialize Smart-ID authentication with invalid method get"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "idCode", "30303039914")
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(cookieMap, "SESSION", flow.sessionId)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullSidInitUrl, cookieMap, paramsMap, additionalParamsMap)
        assertEquals(500, response.statusCode(), "Correct HTTP status code is returned")
        assertThat(response.body().jsonPath().get("message").toString(), equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
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
        assertEquals(400, initSidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", initSidAuthenticationSession.getContentType(), "Correct Content-Type is returned")
        assertThat(initSidAuthenticationSession.body().jsonPath().get("message"), containsString(errorMessage))

        where:
        idCode         | additionalParameterName | additionalParameterValue               | label                        || errorMessage
        "60001019938"  | _                       | _                                      | "invalid idCode checksum"    || "Isikukood ei ole korrektne."
        _              | _                       | _                                      | "missing idCode"             || "Isikukood ei ole korrektne."
        "600010199399" | _                       | _                                      | "too long idCode"            || "Isikukood ei ole korrektne."
        "60001329939"  | _                       | _                                      | "wrong date inside idCode"   || "Isikukood ei ole korrektne."
        "6000"         | _                       | _                                      | "too short idCode"           || "Isikukood ei ole korrektne."
        "38500030556"  | _                       | _                                      | "invalid month in idCode"    || "Isikukood ei ole korrektne."
        "60001017716"  | "idCode"                | "60001017727"                          | "multiple idCode parameters" || "Multiple request parameters with the same name not allowed"
        "60001017716"  | "_csrf"                 | "d7860443-a0cc-45db-ad68-3c9300c0b3bb" | "multiple _csrf parameters"  || "Multiple request parameters with the same name not allowed"
    }

    @Unroll
    @Feature("SID_AUTH_INIT_ENDPOINT")
    def "initialize Smart-ID authentication with no smart-id contract: #label"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid",login_locale)
        Steps.initSidAuthSession(flow, flow.sessionId, "29101290233", Collections.emptyMap())
        Response pollResponse = Steps.pollSidResponse(flow, 1000L)
        assertEquals(400, pollResponse.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", pollResponse.getContentType(), "Correct Content-Type is returned")
        assertThat(pollResponse.body().jsonPath().get("message"), containsString(errorMessage))
        assertTrue(pollResponse.body().jsonPath().get("incident_nr").toString().size() > 15)

        where:
        login_locale | label             || errorMessage
        "et"         | "Estonian locale" || "Kasutajal puudub"
        "en"         | "English locale"  || "User has no Smart-ID account."
        "ru"         | "Russian locale"  || "У пользователя нет учетной записи Smart-ID."
    }

    @Unroll
    @Feature("SID_AUTH_POLL_RESPONSE_COMPLETED_ERRORS")
    def "initialize Smart-ID authentication with scenario: #label et"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid", "et")
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, idCode, Collections.emptyMap())
        assertEquals(200, initSidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response pollResponse = Steps.pollSidResponse(flow, 3000L)
        String messageText = "Correct HTTP status code is returned. Response body: " + pollResponse.body().jsonPath().prettify()
        assertEquals(400, pollResponse.statusCode(), messageText)
        assertEquals("application/json;charset=UTF-8", pollResponse.getContentType(), "Correct Content-Type is returned")
        assertThat(pollResponse.body().jsonPath().get("message"), startsWith(errorMessage))
        assertThat(pollResponse.body().jsonPath().get("reportable") as Boolean, is(false))

        where:
        idCode        | label                                             || errorMessage
        "30403039917" | "USER_REFUSED"                                    || "Kasutaja katkestas autentimise Smart-ID rakenduses."
        "30403039928" | "USER_REFUSED_DISPLAYTEXTANDPIN"                  || "Kasutaja katkestas Smart-ID rakenduses PIN koodi sisestamise."
        "30403039939" | "USER_REFUSED_VC_CHOICE"                          || "Kasutaja katkestas Smart-ID rakenduses kontrollkoodi valiku."
        "30403039946" | "USER_REFUSED_CONFIRMATIONMESSAGE"                || "Kasutaja katkestas autentimise Smart-ID rakenduses kinnitusekraanil."
        "30403039950" | "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE" || "Kasutaja katkestas autentimise Smart-ID rakenduses kontrollkoodi kinnituskraanil."
        "30403039961" | "USER_REFUSED_CERT_CHOICE"                        || "Kasutajal on mitu Smart-ID kontot ja ühe kontoga tühistati autentimine."
        "30403039972" | "WRONG_VC"                                        || "Kasutaja valis Smart-ID rakenduses vale kontrollkoodi."
    }

    @Unroll
    @Feature("SID_AUTH_POLL_RESPONSE_COMPLETED_ERRORS")
    def "initialize Smart-ID authentication with scenario: #label en"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid", "en")
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, idCode, Collections.emptyMap())
        assertEquals(200, initSidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response pollResponse = Steps.pollSidResponse(flow, 3000L)
        String messageText = "Correct HTTP status code is returned. Response body: " + pollResponse.body().jsonPath().prettify()
        assertEquals(400, pollResponse.statusCode(), messageText)
        assertEquals("application/json;charset=UTF-8", pollResponse.getContentType(), "Correct Content-Type is returned")
        assertThat(pollResponse.body().jsonPath().get("message"), startsWith(errorMessage))
        assertThat(pollResponse.body().jsonPath().get("reportable") as Boolean, is(false))


        where:
        idCode        | label                                             || errorMessage
        "30403039917" | "USER_REFUSED"                                    || "User cancelled authentication in the Smart-ID app."
        "30403039928" | "USER_REFUSED_DISPLAYTEXTANDPIN"                  || "User cancelled PIN code entry in the Smart-ID app."
        "30403039939" | "USER_REFUSED_VC_CHOICE"                          || "User cancelled verification code choice in the Smart-ID app."
        "30403039946" | "USER_REFUSED_CONFIRMATIONMESSAGE"                || "User cancelled authentication on the confirmation screen in the Smart-ID app."
        "30403039950" | "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE" || "User cancelled authentication on the verification code choice confirmation screen in the Smart-ID app."
        "30403039961" | "USER_REFUSED_CERT_CHOICE"                        || "User has multiple Smart-ID accounts and one of them has cancelled authentication."
        "30403039972" | "WRONG_VC"                                        || "User chose the wrong verification code in the Smart-ID app."
    }

    @Unroll
    @Feature("SID_AUTH_POLL_RESPONSE_COMPLETED_ERRORS")
    def "initialize Smart-ID authentication with scenario: #label ru"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid", "ru")
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, idCode, Collections.emptyMap())
        assertEquals(200, initSidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response pollResponse = Steps.pollSidResponse(flow, 3000L)
        String messageText = "Correct HTTP status code is returned. Response body: " + pollResponse.body().jsonPath().prettify()
        assertEquals(400, pollResponse.statusCode(), messageText)
        assertEquals("application/json;charset=UTF-8", pollResponse.getContentType(), "Correct Content-Type is returned")
        assertThat(pollResponse.body().jsonPath().get("message"), startsWith(errorMessage))
        assertThat(pollResponse.body().jsonPath().get("reportable") as Boolean, is(false))


        where:
        idCode        | label                                             || errorMessage
        "30403039917" | "USER_REFUSED"                                    || "Пользователь прервал аутентификацию в приложении Smart-ID."
        "30403039928" | "USER_REFUSED_DISPLAYTEXTANDPIN"                  || "Пользователь отменил ввод PIN-кода в приложении Smart-ID."
        "30403039939" | "USER_REFUSED_VC_CHOICE"                          || "Пользователь отменил выбор кода подтверждения в приложении Smart-ID."
        "30403039946" | "USER_REFUSED_CONFIRMATIONMESSAGE"                || "Пользователь отменил аутентификацию на экране подтверждения в приложении Smart-ID."
        "30403039950" | "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE" || "Пользователь отменил аутентификацию на экране подтверждения контрольного кода в приложении Smart-ID."
        "30403039961" | "USER_REFUSED_CERT_CHOICE"                        || "У пользователя несколько учетных записей Smart-ID, и одна из них отменила аутентификацию."
        "30403039972" | "WRONG_VC"                                        || "Пользователь выбрал неправильный код подтверждения в приложении Smart-ID."
    }

    @Unroll
    @Feature("SID_AUTH_POLL_RESPONSE_TIMEOUT_ERROR")
    def "initialize Smart-ID authentication with scenario: TIMEOUT #login_locale"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid", login_locale)
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, idCode, Collections.emptyMap())
        assertEquals(200, initSidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response pollResponse = Steps.pollSidResponse(flow, 10000L)
        String messageText = "Correct HTTP status code is returned. Response body: " + pollResponse.body().jsonPath().prettify()
        assertEquals(400, pollResponse.statusCode(), messageText)
        assertEquals("application/json;charset=UTF-8", pollResponse.getContentType(), "Correct Content-Type is returned")
        assertThat(pollResponse.body().jsonPath().get("message"), startsWith(errorMessage))
        assertThat(pollResponse.body().jsonPath().get("reportable") as Boolean, is(false))


        where:
        idCode        | login_locale    || errorMessage
        "30403039983" | "et"            || "Kasutaja ei autentinud Smart-ID rakenduses oodatud aja jooksul. Palun proovige uuesti."
        "30403039983" | "en"            || "User did not authenticate in the Smart-ID app within the required time. Please try again."
        "30403039983" | "ru"            || "Пользователь не прошел аутентификацию в приложении Smart-ID в течение требуемого времени. Пожалуйста, попробуйте еще раз."
    }

    @Unroll
    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("SID_AUTH_PENDING")
    def "poll Smart-ID authentication session"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, "30403039983", additionalParamsMap)
        assertEquals(200, initSidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response response = Requests.pollSid(flow)
        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertEquals("PENDING", response.body().jsonPath().get("status"), "Correct Mobile-ID status")
    }

    @Unroll
    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    def "poll Smart-ID authentication session with invalid session ID"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, "30403039983", additionalParamsMap)
        assertEquals(200, initSidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        flow.setSessionId("1234567")
        Response response = Requests.pollSid(flow)
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertEquals("Teie seanssi ei leitud! Seanss aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"), "Correct error message is returned")
    }

    @Unroll
    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("SID_AUTH_SUCCESS")
    def "poll Smart-ID authentication with session complete"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, "30303039914", additionalParamsMap)
        assertEquals(200, initSidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response response = Steps.pollSidResponse(flow)
        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertEquals("COMPLETED", response.body().jsonPath().get("status"), "Correct Mobile-ID status")
    }

    //TODO: AUT-630
    @Unroll
    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    def "poll Smart-ID authentication with invalid method post"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, "30303039914", additionalParamsMap)
        assertEquals(200, initSidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullSidPollUrl)
        assertEquals(500, response.statusCode(), "Correct HTTP status code is returned")
        assertThat(response.body().jsonPath().get("message").toString(), equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
    }

    @Unroll
    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    @Feature("SID_AUTH_CANCELED")
    def "cancel Smart-ID authentication"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, "30303039914", additionalParamsMap)
        assertEquals(200, initSidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullSidCancelUrl)
        assertEquals(302, response.statusCode(), "Correct HTTP status code is returned")
        assertThat(response.getHeader("location"), startsWith(flow.loginService.initUrl + "?login_challenge=" + flow.loginChallenge))
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
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, "30303039914", additionalParamsMap)
        assertEquals(200, initSidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullSidCancelUrl)
        assertEquals(302, response.statusCode(), "Correct HTTP status code is returned")
        Steps.verifyResponseHeaders(response)
    }

    @Unroll
    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    def "cancel Smart-ID authentication with invalid session ID"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, "30303039914", additionalParamsMap)
        assertEquals(200, initSidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")

        flow.setSessionId("1234567")
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullSidCancelUrl)
        assertEquals(403, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")

        assertEquals("Forbidden", response.body().jsonPath().get("error"), "Correct error text is returned")
        String errorMessage = "Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."
        assertEquals(errorMessage, response.body().jsonPath().get("message"), "Correct error message is returned")
    }

    //TODO: AUT-630
    @Unroll
    @Feature("SID_AUTH_STATUS_CHECK_ENDPOINT")
    def "cancel Smart-ID authentication with invalid method get"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initSidAuthenticationSession = Steps.initSidAuthSession(flow, flow.sessionId, "30303039914", additionalParamsMap)
        assertEquals(200, initSidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")

        Response response = Requests.getRequestWithSessionId(flow, flow.loginService.fullSidCancelUrl)
        assertEquals(500, response.statusCode(), "Correct HTTP status code is returned")
        assertThat(response.body().jsonPath().get("message").toString(), equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
    }
}
