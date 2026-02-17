package ee.ria.tara.step

import ee.ria.tara.Flow
import ee.ria.tara.Requests
import ee.ria.tara.Steps
import io.qameta.allure.Step
import io.restassured.response.Response
import org.apache.http.HttpStatus
import spock.util.concurrent.PollingConditions

import static org.hamcrest.Matchers.equalTo

class SidSteps {

    /* ============================================================
       AUTHENTICATION FLOWS
       ============================================================ */

    @Step("Authenticate with Smart-ID push notification flow")
    static Response authenticateWithSidNotificationFlow(Flow flow, String idCode) {
        initSidAuthSession(flow, idCode)
                .then()
                .statusCode(HttpStatus.SC_OK)
        pollSidNotificationSessionStatus(flow)
                .then()
                .statusCode(HttpStatus.SC_OK)
                .body("status", equalTo("COMPLETED"))
        return authenticateWithSidCommon(flow)
    }

    @Step("Authenticate with Smart-ID QR code flow")
    static Response authenticateWithSidQrFlow(Flow flow, String documentNumber) {
        initSidQrCodeAuthSession(flow)
        String deviceLink = getSidQrCodeDeviceLink(flow)
        initSidQrCodeMockAuth(flow, documentNumber, deviceLink)
        pollSidQrCodeSessionStatus(flow)
                .then()
                .statusCode(HttpStatus.SC_OK)
                .body("status", equalTo("COMPLETED"))
        return authenticateWithSidCommon(flow)
    }

    @Step("Authenticate with Smart-ID Web2App flow")
    static Response authenticateWithSidWeb2AppFlow(Flow flow, String documentNumber) {
        Response authInitResponse = initSidWeb2AppAuthSession(flow)
        String deviceLink = authInitResponse.jsonPath().getString("deviceLink")
        // TODO: currently fails, waiting mock adjustments
        initSidWeb2AppMockAuth(flow, documentNumber, deviceLink)
        // TODO: perform callback, waiting mock adjustments
        //  Test if this call is required or can go straight to poll?

        // TODO: get parameters from mock response?
        Map params = [_csrf                : flow.csrf,
                      value                : "TODO: get value",
                      sessionSecretDigest  : "TODO: get sessionSecretDigest",
                      userChallengeVerifier: "TODO: get userChallengeVerifier"
        ]
        pollSidWeb2AppSessionStatusAfterCallback(flow, params)
                .then()
                .statusCode(HttpStatus.SC_OK)
                .body("status", equalTo("COMPLETED"))
        return authenticateWithSidCommon(flow)
    }

    static Response authenticateWithSidCommon(Flow flow) {
        Response acceptResponse = Requests.postRequest(flow, flow.loginService.fullAuthAcceptUrl)
        acceptResponse.then().statusCode(HttpStatus.SC_MOVED_TEMPORARILY)
        Response oidcServiceResponse = Steps.loginVerifier(flow, acceptResponse)
        oidcServiceResponse.then().statusCode(HttpStatus.SC_MOVED_TEMPORARILY)
        return Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
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
    static Response initSidQrCodeAuthSession(Flow flow) {
        Response response = Requests.postRequest(flow, flow.loginService.sidQrCodeInitUrl)
        response.then().statusCode(HttpStatus.SC_OK)
        return response
    }

    @Step("Initialize Smart-ID device link same-device authentication")
    static Response initSidWeb2AppAuthSession(Flow flow) {
        Response response = Requests.postRequest(flow, flow.loginService.sidWeb2AppInitUrl)
        response.then().statusCode(HttpStatus.SC_OK)
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

    static Response pollSidQrCodeSessionStatus(Flow flow, long pollingIntevalMillis = 2000L) {
        return pollSidWhilePending(pollingIntevalMillis) {
            Requests.pollSid(flow, flow.loginService.sidQrCodePollUrl)
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
            if (response.jsonPath().getString("status") != "PENDING") {
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

    static Response initSidQrCodeMockAuth(Flow flow, String documentNumber, String deviceLink) {
        return initSidDeviceLinkMockAuth(flow, documentNumber, deviceLink, "QR")
    }

    static Response initSidWeb2AppMockAuth(Flow flow, String documentNumber, String deviceLink) {
        return initSidDeviceLinkMockAuth(flow, documentNumber, deviceLink, "Web2App")
    }

    static Response initSidDeviceLinkMockAuth(Flow flow, String documentNumber, String deviceLink, String flowType) {
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

    static String getSidQrCodeDeviceLink(Flow flow) {
        def conditions = new PollingConditions(timeout: 3, delay: 0.1)
        String deviceLink = null

        conditions.eventually {
            def response = Requests.pollSid(flow, flow.loginService.sidQrCodePollUrl)
            deviceLink = response.jsonPath().getString("deviceLink")
            assert deviceLink != null
        }

        return deviceLink
    }

    static Map sidWeb2AppCallbackPollDefaultParams(flow) {
        [_csrf                : flow.csrf,
         value                : "test",
         sessionSecretDigest  : "test",
         userChallengeVerifier: "test"
        ]
    }
}
