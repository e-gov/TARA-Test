package ee.ria.tara.smartid.qrcode

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import ee.ria.tara.*
import ee.ria.tara.configuration.ConfigHolder
import ee.ria.tara.model.ErrorMessage
import ee.ria.tara.step.SidSteps
import ee.ria.tara.testdata.SidAccount
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.http.HttpStatus
import spock.lang.Ignore
import spock.lang.Issue
import spock.lang.Tag

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*

class SidQrAuthenticationSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Tag("sid-device-link-mock")
    def "Authenticate with Smart-ID QR code flow"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Response sidAuthResponse = SidSteps.authenticateWithSidQrFlow(flow, SidAccount.OK)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, sidAuthResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Incorrect audience", claims.audience[0], is(ClientStore.mockPublic.clientId))
        Steps.verifyPersonClaims(claims, SidAccount.OK)
    }

    @Issue("AUT-3178")
    @Tag("sid-device-link-mock")
    def "Authentication with Smart-ID QR code not allowed for non-EE account"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidQrCodeAuthSession(flow)
        String deviceLink = SidSteps.getSidQrCodeDeviceLink(flow)
        SidSteps.initSidDeviceLinkMockAuth(flow, account, deviceLink)

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
        account << [SidAccount.OK_LT, SidAccount.OK_LV, SidAccount.OK_BE]
    }

    def "Initialize Smart-ID QR code authentication"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")

        when:
        Response response = SidSteps.initSidQrCodeAuthSession(flow)

        then:
        assertThat("Incorrect HTTP status code", response.statusCode, is(HttpStatus.SC_OK))
        assertThat("Incorrect Content-Type", response.contentType, is("text/html;charset=UTF-8"))
        String qrCodeDiv = response.htmlPath().getString("**.find { it -> it.@id == 'sidQrCode' }")
        assertThat("QR code element missing", qrCodeDiv, notNullValue())
    }

    def "Smart-ID QR code polling returns valid device link"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidQrCodeAuthSession(flow)

        when:
        String deviceLink = SidSteps.getSidQrCodeDeviceLink(flow)

        then:
        assertThat("Incorrect device link base", deviceLink, startsWith(ConfigHolder.testConf.sidDeviceLinkBase()))

        Map deviceLinkParams = Utils.parseQueryParams(deviceLink)
        assertThat("Incorrect device link type", deviceLinkParams.deviceLinkType, equalTo("QR"))
        assertThat("Missing elapsed seconds", deviceLinkParams.elapsedSeconds, notNullValue())
        assertThat("Missing session token", deviceLinkParams.sessionToken, notNullValue())
        assertThat("Incorrect session type", deviceLinkParams.sessionType, equalTo("auth"))
        assertThat("Incorrect version", deviceLinkParams.version, equalTo("1.0"))
        assertThat("Incorrect language", deviceLinkParams.lang, equalTo("est"))
        assertThat("Missing auth code", deviceLinkParams.authCode, notNullValue())
    }

    @Issue("AUT-3178")
    @Tag("sid-device-link-mock")
    def "Initialize Smart-ID QR code authentication with scenario: #account et"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid", "et")
        SidSteps.initSidQrCodeAuthSession(flow)
        String deviceLink = SidSteps.getSidQrCodeDeviceLink(flow)
        SidSteps.initSidDeviceLinkMockAuth(flow, account, deviceLink)

        when:
        Response pollResponse = SidSteps.pollSidQrCodeSessionStatus(flow, 3000L)

        then:
        pollResponse.then()
                .statusCode(HttpStatus.SC_OK)
                .contentType("application/json;charset=UTF-8")
                .body(
                        "status", equalTo("FAILED"),
                        "error", equalTo(errorMessage.name()),
                        "message", equalTo(errorMessage.message)
                )

        where:
        account                                      || errorMessage
        SidAccount.USER_REFUSED                      || ErrorMessage.SID_USER_REFUSED
        SidAccount.USER_REFUSED_CONFIRMATIONMESSAGE  || ErrorMessage.SID_USER_REFUSED_CONFIRMATIONMESSAGE
    }

    @Issue("AUT-3178")
    @Tag("sid-device-link-mock")
    def "Initialize Smart-ID QR code authentication with scenario: TIMEOUT"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidQrCodeAuthSession(flow)
        String deviceLink = SidSteps.getSidQrCodeDeviceLink(flow)
        SidSteps.initSidDeviceLinkMockAuth(flow, SidAccount.TIMEOUT, deviceLink)

        when:
        Response pollResponse = SidSteps.pollSidQrCodeSessionStatus(flow, 10000L)

        then:
        ErrorMessage error = ErrorMessage.SID_SESSION_TIMEOUT
        pollResponse.then()
                .statusCode(HttpStatus.SC_OK)
                .contentType("application/json;charset=UTF-8")
                .body(
                        "status", equalTo("FAILED"),
                        "error", equalTo(error.name()),
                        "message", equalTo(error.message)
                )
    }

    def "Poll Smart-ID QR code authentication session"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidQrCodeAuthSession(flow)

        when:
        Response response = Requests.pollSid(flow, flow.loginService.sidQrCodePollUrl)

        then:
        assertThat("Incorrect HTTP status code", response.statusCode, is(HttpStatus.SC_OK))
        assertThat("Incorrect Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Incorrect Smart-ID status", response.jsonPath().getString("status"), is("PENDING"))
    }

    @Tag("sid-device-link-mock")
    def "Poll Smart-ID QR code authentication with session complete"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidQrCodeAuthSession(flow)
        String deviceLink = SidSteps.getSidQrCodeDeviceLink(flow)
        SidSteps.initSidDeviceLinkMockAuth(flow, SidAccount.OK, deviceLink)

        when:
        Response response = SidSteps.pollSidQrCodeSessionStatus(flow)

        then:
        assertThat("Incorrect HTTP status code", response.statusCode, is(HttpStatus.SC_OK))
        assertThat("Incorrect Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Incorrect Smart-ID status", response.jsonPath().getString("status"), is("COMPLETED"))
    }

    def "Cancel Smart-ID QR code authentication"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        SidSteps.initSidQrCodeAuthSession(flow)

        when:
        Response response = Requests.postRequest(flow, flow.loginService.sidQrCodeCancelUrl)

        then:
        assertThat("Incorrect HTTP status code", response.statusCode, is(HttpStatus.SC_MOVED_TEMPORARILY))
        assertThat("Incorrect location header", response.header("location"), is(flow.loginService.initUrl + "?login_challenge=" + flow.loginChallenge + "&lang=et"))
        Steps.verifyResponseHeaders(response)
    }

    @Ignore("AUT-3204")
    @Issue("AUT-3204")
    @Tag("sid-device-link-mock")
    def "Smart-ID QR code authentication with long name"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid smartid")
        Response sidAuthResponse = SidSteps.authenticateWithSidQrFlow(flow, SidAccount.LONG_NAME)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, sidAuthResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        Steps.verifyPersonClaims(claims, SidAccount.LONG_NAME)
    }
}
