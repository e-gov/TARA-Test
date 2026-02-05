package ee.ria.tara.step

import ee.ria.tara.Flow
import ee.ria.tara.Requests
import ee.ria.tara.Steps
import io.qameta.allure.Step
import io.restassured.response.Response
import org.apache.http.HttpStatus
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers

class SidSteps {

    /* ============================================================
       AUTHENTICATION FLOWS
       ============================================================ */

    @Step("Authenticate with Smart-ID push notification flow")
    static Response authenticateWithSidNotificationFlow(Flow flow, String idCode) {
        Response sidInit = initSidAuthSession(flow, idCode)
        MatcherAssert.assertThat("Correct HTTP status code", sidInit.statusCode, Matchers.is(200))
        Response sidPollResult = pollSidNotificationSessionStatus(flow)
        MatcherAssert.assertThat("Correct HTTP status code", sidPollResult.statusCode, Matchers.is(200))
        MatcherAssert.assertThat(sidPollResult.jsonPath().getString("status"), Matchers.is("COMPLETED"))
        return authenticateWithSidCommon(flow)
    }

    @Step("Authenticate with Smart-ID QR code flow")
    static Response authenticateWithSidQRFlow(Flow flow, String documentNumber) {
        initSidQRCodeAuthSession(flow)
        String deviceLink = getSidQRCodeDeviceLink(flow)
        initQrCodeMock(flow, documentNumber, deviceLink)
        Response sidPollResult = pollSidQRCodeSessionStatus(flow)
        MatcherAssert.assertThat("Correct HTTP status code", sidPollResult.statusCode, Matchers.is(200))
        MatcherAssert.assertThat(sidPollResult.jsonPath().getString("status"), Matchers.is("COMPLETED"))
        return authenticateWithSidCommon(flow)
    }

    @Step("Authenticate with Smart-ID Web2App flow")
    static Response authenticateWithSidWeb2AppFlow(Flow flow, String documentNumber) {
        Response response = initSidWeb2AppAuthSession(flow)
        String deviceLink = response.getHeader("location")
        // TODO: currently fails, waiting mock adjustments
        initWeb2AppMock(flow, documentNumber, deviceLink)
        // TODO: perform callback, waiting mock adjustments
        //  Test if this call is required or can go straight to poll?

        // TODO: get parameters from mock response?
        Map params = [_csrf                : flow.csrf,
                      value                : "TODO: get value",
                      sessionSecretDigest  : "TODO: get sessionSecretDigest",
                      userChallengeVerifier: "TODO: get userChallengeVerifier"
        ]
        Response sidPollResult = pollSidWeb2AppSessionStatusAfterCallback(flow, params)
        MatcherAssert.assertThat("Correct HTTP status code", sidPollResult.statusCode, Matchers.is(200))
        MatcherAssert.assertThat(sidPollResult.jsonPath().getString("status"), Matchers.is("COMPLETED"))
        return authenticateWithSidCommon(flow)
    }

    static authenticateWithSidCommon(Flow flow) {
        Response acceptResponse = Requests.postRequest(flow, flow.loginService.fullAuthAcceptUrl)
        MatcherAssert.assertThat("Correct HTTP status code", acceptResponse.statusCode, Matchers.is(302))
        Response oidcServiceResponse = Steps.loginVerifier(flow, acceptResponse)
        MatcherAssert.assertThat("Correct HTTP status code", oidcServiceResponse.statusCode, Matchers.is(302))
        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        return consentResponse
    }

    /* ============================================================
       SESSION INITIALIZATION
       ============================================================ */

    @Step("Initialize Smart-ID push notification authentication")
    static Response initSidAuthSession(Flow flow, Object idCode) {
        Map formParamsMap = ["_csrf": flow.csrf,
                             idCode : idCode]
        Response response = Requests.postRequestWithParams(flow, flow.loginService.sidInitUrl, formParamsMap)
        response.then().statusCode(HttpStatus.SC_OK)
        return response
    }

    @Step("Initialize Smart-ID device link cross-device authentication")
    static Response initSidQRCodeAuthSession(Flow flow) {
        Response response = Requests.postRequest(flow, flow.loginService.sidQRCodeInitUrl)
        response.then().statusCode(HttpStatus.SC_OK)
        return response
    }

    @Step("Initialize Smart-ID device link same-device authentication")
    static Response initSidWeb2AppAuthSession(Flow flow) {
        Response response = Requests.getRequest(flow, flow.loginService.sidWeb2AppInitUrl)
        // TODO: AUT-2567
//         Response response = Requests.postRequest(flow, flow.loginService.sidWeb2AppInitUrl)
        response.then().statusCode(HttpStatus.SC_SEE_OTHER)
        return response
    }

    /* ============================================================
       POLLING
       ============================================================ */

    static Response pollSidNotificationSessionStatus(Flow flow, long pollingIntevalMillis = 2000L) {
        return pollSidWhilePending(pollingIntevalMillis) {
            Requests.pollSid(flow, flow.loginService.sidPollUrl)
        }
    }

    static Response pollSidQRCodeSessionStatus(Flow flow, long pollingIntevalMillis = 2000L) {
        return pollSidWhilePending(pollingIntevalMillis) {
            Requests.pollSid(flow, flow.loginService.sidQRCodePollUrl)
        }
    }

    static Response pollSidWeb2AppSessionStatus(Flow flow, long pollingIntevalMillis = 2000L) {
        return pollSidWhilePending(pollingIntevalMillis) {
            Requests.pollSid(flow, flow.loginService.sidWeb2AppPollUrl)
        }
    }

    static Response pollSidWeb2AppSessionStatusAfterCallback(Flow flow, Map params, long pollingIntevalMillis = 2000L) {
        return pollSidWhilePending(pollingIntevalMillis) {
            Requests.getRequestWithParams(flow, flow.loginService.sidWeb2AppCallbackPollUrl, params)
        }
    }

    @Step("Polling Smart-ID authentication session status")
    static Response pollSidWhilePending(long pollingIntevalMillis, Closure<Response> request) {
        int counter = 0
        Response response = null
        while (counter < 20) {
            response = request.call()
            if (response.jsonPath().get("status") != "PENDING") {
                break
            }
            ++counter
            sleep(pollingIntevalMillis)
        }
        return response
    }

    /* ============================================================
       DEVICE-LINK MOCK INTERACTIONS
       ============================================================ */

    static Response initQrCodeMock(Flow flow, String documentNumber, String deviceLink) {
        return initMockFlow(flow, documentNumber, deviceLink, "QR")
    }

    static Response initWeb2AppMock(Flow flow, String documentNumber, String deviceLink) {
        return initMockFlow(flow, documentNumber, deviceLink, "Web2App")
    }

    static Response initMockFlow(Flow flow, String documentNumber, String deviceLink, String flowType) {
        String cookie = flow.cookieFilter.cookieStore.cookies
                .find { it.name == "__Host-SESSION" }
                ?.value
                ?.with { "__Host-SESSION=$it" }

        def mockRequest = [
                documentNumber: documentNumber,
                deviceLink    : deviceLink,
                flowType      : flowType,
                browserCookie : cookie
        ]

        def response = Requests.postDeviceLinkToMock(mockRequest)
        response.then().statusCode(HttpStatus.SC_OK)
        return response
    }

    /* ============================================================
       HELPERS
       ============================================================ */

    static String getSidQRCodeDeviceLink(Flow flow) {
        int counter = 0
        Response response = null
        while (counter < 20) {
            response = Requests.pollSid(flow, flow.loginService.sidQRCodePollUrl)
            if (response.jsonPath().get("deviceLink") != null) {
                break
            }
            ++counter
            sleep(100)
        }
        return response.path("deviceLink")
    }
}
