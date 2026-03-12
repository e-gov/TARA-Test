package ee.ria.tara.smartid.web2app

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import ee.ria.tara.*
import ee.ria.tara.configuration.ConfigHolder
import ee.ria.tara.model.ErrorMessage
import ee.ria.tara.step.SidSteps
import ee.ria.tara.util.ErrorValidator
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.http.HttpStatus
import spock.lang.Ignore
import spock.lang.Tag

import static io.restassured.RestAssured.given
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*

class SidW2aAuthenticationSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Ignore("AUT-2509")
    @Tag("sid-device-link-mock")
    def "Authenticate with Smart-id web2app flow"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Response sidAuthResponse = SidSteps.authenticateWithSidWeb2AppFlow(flow, "PNOEE-40404040009-MOCK-Q")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, sidAuthResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Incorrect audience", claims.audience[0], is(ClientStore.mockPublic.clientId))
        assertThat("Incorrect subject", claims.subject, is("EE40404040009"))
        assertThat("Incorrect given name", claims.getJSONObjectClaim("profile_attributes")["given_name"], is("OK"))
        assertThat("Incorrect family game", claims.getJSONObjectClaim("profile_attributes")["family_name"], is("TEST"))
        assertThat("Incorrect date of birth", claims.getJSONObjectClaim("profile_attributes")["date_of_birth"], is("1904-04-04"))
    }

    @Ignore("AUT-2662")
    @Tag("sid-device-link-mock")
    def "Authentication with Smart-ID web2app not allowed for non-EE account"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Response authInitResponse = SidSteps.initSidWeb2AppAuthSession(flow)
        String deviceLink = authInitResponse.jsonPath().getString("deviceLink")
        SidSteps.initSidWeb2AppMockAuth(flow, documentNumber, deviceLink)

        when:
        Response pollResponse = SidSteps.pollSidQrCodeSessionStatus(flow)

        then:
        ErrorMessage error = ErrorMessage.SID_COUNTRY_NOT_ALLOWED
        pollResponse.then()
                .statusCode(HttpStatus.SC_OK)
                .contentType("application/json;charset=UTF-8")
                .body(
                        "status", equalTo("FAILED"),
                        "error", equalTo(error.name()),
                        "message", equalTo(error.message)
                )

        where:
        documentNumber << [
                "PNOLT-40404040009-MOCK-Q",
                "PNOLV-040404-10003-DEMO-Q",
                "PNOBE-04040400287-MOCK-Q"
        ]
    }

    def "Initialize Smart-ID web2app authentication returns valid device link"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")

        when:
        Response authInitResponse = SidSteps.initSidWeb2AppAuthSession(flow)

        then:
        String deviceLink = authInitResponse.jsonPath().getString("deviceLink")
        assertThat("Incorrect device link base", deviceLink, startsWith(ConfigHolder.testConf.sidDeviceLinkBase()))

        Map deviceLinkParams = Utils.parseQueryParams(deviceLink)
        assertThat("Incorrect device link type", deviceLinkParams.deviceLinkType, equalTo("Web2App"))
        assertThat("Missing session token", deviceLinkParams.sessionToken, notNullValue())
        assertThat("Incorrect session type", deviceLinkParams.sessionType, equalTo("auth"))
        assertThat("Incorrect version", deviceLinkParams.version, equalTo("1.0"))
        assertThat("Incorrect language", deviceLinkParams.lang, equalTo("est"))
        assertThat("Missing auth code", deviceLinkParams.authCode, notNullValue())
    }

    @Ignore("AUT-2509")
    @Tag("sid-device-link-mock")
    def "Initialize Smart-ID web2app authentication with scenario: #label et"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid", "et")
        Response authInitResponse = SidSteps.initSidWeb2AppAuthSession(flow)
        String deviceLink = authInitResponse.jsonPath().getString("deviceLink")
        SidSteps.initSidWeb2AppMockAuth(flow, documentNumber, deviceLink)
        Map pollQueryParams = [sessionToken: Utils.parseQueryParams(deviceLink).sessionToken]

        when:
        Response pollResponse = SidSteps.pollSidWeb2AppSessionStatus(flow, pollQueryParams, 3000L)

        then:
        ErrorValidator.validate(pollResponse, HttpStatus.SC_BAD_REQUEST, errorMessage)
        pollResponse.then().body("reportable", is(false))

        where:
        documentNumber | label                              || errorMessage
        "TODO"         | "USER_REFUSED"                     || "Kasutaja katkestas autentimise<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses."
        "TODO"         | "USER_REFUSED_DISPLAYTEXTANDPIN"   || "Kasutaja katkestas<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses PIN koodi sisestamise."
        "TODO"         | "USER_REFUSED_CONFIRMATIONMESSAGE" || "Kasutaja katkestas autentimise<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses kinnitusekraanil."
    }


    @Ignore("Slow without dedicated test account (takes over 2min)")
    def "Initialize Smart-ID web2app authentication with scenario: TIMEOUT"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Response authInitResponse = SidSteps.initSidWeb2AppAuthSession(flow)
        String deviceLink = authInitResponse.jsonPath().getString("deviceLink")
        Map pollQueryParams = [sessionToken: Utils.parseQueryParams(deviceLink).sessionToken]

        when:
        Response pollResponse = SidSteps.pollSidWeb2AppSessionStatus(flow, pollQueryParams, 10000L)

        then:
        ErrorValidator.validate(pollResponse, ErrorMessage.SID_SESSION_TIMEOUT)
        pollResponse.then().body("reportable", is(false))
    }

    def "Poll Smart-ID web2app authentication session"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Response authInitResponse = SidSteps.initSidWeb2AppAuthSession(flow)
        String deviceLink = authInitResponse.jsonPath().getString("deviceLink")
        Map queryParams = [sessionToken: Utils.parseQueryParams(deviceLink).sessionToken]

        when:
        Response response = Requests.getRequestWithParams(flow, flow.loginService.sidWeb2AppPollUrl, queryParams)

        then:
        assertThat("Incorrect HTTP status code", response.statusCode, is(HttpStatus.SC_OK))
        assertThat("Incorrect Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Incorrect Smart-ID status", response.jsonPath().getString("status"), is("PENDING"))
    }

    @Tag("sid-device-link-mock")
    def "Poll Smart-ID web2app authentication with session complete"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Response authInitResponse = SidSteps.initSidWeb2AppAuthSession(flow)
        String deviceLink = authInitResponse.jsonPath().getString("deviceLink")
        SidSteps.initSidWeb2AppMockAuth(flow, "PNOEE-40404040009-MOCK-Q", deviceLink)
        Map pollQueryParams = [sessionToken: Utils.parseQueryParams(deviceLink).sessionToken]

        when:
        Response response = SidSteps.pollSidWeb2AppSessionStatus(flow, pollQueryParams)

        then:
        assertThat("Incorrect HTTP status code", response.statusCode, is(HttpStatus.SC_OK))
        assertThat("Incorrect Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Incorrect Smart-ID status", response.jsonPath().getString("status"), is("COMPLETED"))
    }

    def "Cancel Smart-ID web2app polling"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidWeb2AppAuthSession(flow)

        when:
        Response response = Requests.postRequest(flow, flow.loginService.sidWeb2AppPollCancelUrl)

        then:
        assertThat("Incorrect HTTP status code", response.statusCode, is(HttpStatus.SC_MOVED_TEMPORARILY))
        assertThat("Incorrect location header", response.header("location"), is(flow.loginService.initUrl + "?login_challenge=" + flow.loginChallenge + "&lang=et"))
        Steps.verifyResponseHeaders(response)
    }

    def "Cancel Smart-ID web2app post-callback polling"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidWeb2AppAuthSession(flow)

        when:
        Response response = Requests.postRequest(flow, flow.loginService.sidWeb2AppCallbackPollCancelUrl)

        then:
        assertThat("Incorrect HTTP status code", response.statusCode, is(HttpStatus.SC_MOVED_TEMPORARILY))
        assertThat("Incorrect location header", response.header("location"), is(flow.loginService.initUrl + "?login_challenge=" + flow.loginChallenge + "&lang=et"))
        Steps.verifyResponseHeaders(response)
    }

    @Ignore("AUT-2509")
    def "Smart-ID web2app authentication callback"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidWeb2AppAuthSession(flow)

        when:
        Response response = given()
                .cookies(["__Host-SESSION": flow.sessionId])
                .get(flow.loginService.sidWeb2AppCallbackUrl + "?value=TODO") // TODO: acceptable value

        then:
        assertThat("Incorrect HTTP status code", response.statusCode, is(HttpStatus.SC_OK))
        assertThat("Incorrect Content-Type", response.contentType, is("text/html;charset=UTF-8"))
        // TODO: improve validations (more specific locators)
        String buttonLabel = response.htmlPath()
                .getString("**.find { it.name() == 'button' && it.@class?.toString().contains('c-btn--cancel') }.text()")
        assertThat("Incorrect cancel button label", buttonLabel, is("Tühista"))
        String action = response.htmlPath().getString("**.find { it.name() == 'form' && it.@class == 'c-form' }.@action")
        assertThat("Incorrect cancel action path", action, is("/auth/sid/web2app/callback/poll/cancel"))
    }

    def "Poll Smart-ID web2app authentication session post-callback"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidWeb2AppAuthSession(flow)

        when:
        Response callbackPoll = given()
                .cookies(["__Host-SESSION": flow.sessionId])
                .params(SidSteps.sidWeb2AppCallbackPollDefaultParams(flow))
                .get(flow.loginService.sidWeb2AppCallbackPollUrl)

        then:
        assertThat("Incorrect HTTP status code", callbackPoll.statusCode, is(HttpStatus.SC_OK))
        assertThat("Incorrect Content-Type", callbackPoll.contentType, is("application/json;charset=UTF-8"))
        assertThat("Incorrect Smart-ID status", callbackPoll.jsonPath().getString("status"), is("PENDING"))
    }

    @Tag("sid-device-link-mock")
    def "Poll Smart-ID web2app authentication session post-callback with session complete"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Response authInitResponse = SidSteps.initSidWeb2AppAuthSession(flow)

        String deviceLink = authInitResponse.jsonPath().getString("deviceLink")
        SidSteps.initSidWeb2AppMockAuth(flow, "PNOEE-40404040009-MOCK-Q", deviceLink)

        when:
        Response callbackPoll = SidSteps.pollSidWeb2AppSessionStatusAfterCallback(flow, SidSteps.sidWeb2AppCallbackPollDefaultParams(flow))

        then:
        assertThat("Incorrect HTTP status code", callbackPoll.statusCode, is(HttpStatus.SC_OK))
        assertThat("Incorrect Content-Type", callbackPoll.contentType, is("application/json;charset=UTF-8"))
        assertThat("Incorrect Smart-ID status", callbackPoll.jsonPath().getString("status"), is("COMPLETED"))
    }

    def "Poll Smart-ID web2app authentication session post-callback in invalid session status"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")

        when: "Poll Smart-ID authentication with invalid session status"
        Response callbackPoll = given()
                .cookies(["__Host-SESSION": flow.sessionId])
                .params(SidSteps.sidWeb2AppCallbackPollDefaultParams(flow))
                .get(flow.loginService.sidWeb2AppCallbackPollUrl)

        then:
        ErrorValidator.validate(callbackPoll, ErrorMessage.SESSION_STATE_INVALID)
    }

    @Tag("sid-device-link-mock")
    def "Poll Smart-ID web2app authentication session post-callback with #label"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Response authInitResponse = SidSteps.initSidWeb2AppAuthSession(flow)
        String deviceLink = authInitResponse.jsonPath().getString("deviceLink")
        SidSteps.initSidWeb2AppMockAuth(flow, "PNOEE-40404040009-MOCK-Q", deviceLink)

        when:
        Map params = SidSteps.sidWeb2AppCallbackPollDefaultParams(flow)
        paramsModification.call(params)
        Response pollResponse = Requests.getRequestWithParams(flow, flow.loginService.sidWeb2AppCallbackPollUrl, params)

        then:
        ErrorValidator.validate(pollResponse, errorMessage, param)

        where:
        param                   | label                       | paramsModification                || errorMessage
        "value"                 | "missing param: ${param}"   | { it.remove(param) }              || ErrorMessage.MISSING_PARAMETERS
        "sessionSecretDigest"   | "missing param: ${param}"   | { it.remove(param) }              || ErrorMessage.MISSING_PARAMETERS
        "userChallengeVerifier" | "missing param: ${param}"   | { it.remove(param) }              || ErrorMessage.MISSING_PARAMETERS
        "value"                 | "duplicate param: ${param}" | { it[param] = ["test", "test2"] } || ErrorMessage.DUPLICATE_PARAMETERS
        "sessionSecretDigest"   | "duplicate param: ${param}" | { it[param] = ["test", "test2"] } || ErrorMessage.DUPLICATE_PARAMETERS
        "userChallengeVerifier" | "duplicate param: ${param}" | { it[param] = ["test", "test2"] } || ErrorMessage.DUPLICATE_PARAMETERS
    }
}
