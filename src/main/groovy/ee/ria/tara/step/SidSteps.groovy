package ee.ria.tara.step

import ee.ria.tara.Flow
import ee.ria.tara.Requests
import ee.ria.tara.Steps
import ee.ria.tara.Utils
import ee.ria.tara.configuration.ConfigHolder
import ee.ria.tara.testdata.SidAccount
import io.qameta.allure.Step
import io.restassured.response.Response
import org.apache.http.HttpStatus
import spock.util.concurrent.PollingConditions

import static org.hamcrest.Matchers.equalTo

class SidSteps {

    /* ============================================================
       AUTHENTICATION FLOWS
       ============================================================ */

    @Step("Authenticate with Smart-ID QR code flow")
    static Response authenticateWithSidQrFlow(Flow flow, SidAccount account) {
        initSidQrCodeAuthSession(flow)
        String deviceLink = getSidQrCodeDeviceLink(flow)
        initSidDeviceLinkMockAuth(flow, account, deviceLink)
        pollSidQrCodeSessionStatus(flow)
                .then()
                .statusCode(HttpStatus.SC_OK)
                .body("status", equalTo("COMPLETED"))
        return authenticateWithSidCommon(flow)
    }

    @Step("Authenticate with Smart-ID Web2App flow")
    static Response authenticateWithSidWeb2AppFlow(Flow flow, SidAccount account) {
        Response authInitResponse = initSidWeb2AppAuthSession(flow)
        String deviceLink = authInitResponse.jsonPath().getString("deviceLink")
        String callbackUrl = sidMockAuthAndCallback(flow, account, deviceLink)

        pollSidWeb2AppSessionStatusAfterCallback(flow, sidWeb2AppCallbackPollParams(flow, callbackUrl))
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

    static Response pollSidQrCodeSessionStatus(Flow flow, long pollingIntevalMillis = 2000L) {
        return pollSidWhilePending(pollingIntevalMillis) {
            Requests.pollSid(flow, flow.loginService.sidQrCodePollUrl)
        }
    }

    static Response pollSidWeb2AppSessionStatus(Flow flow, Map queryParams, long pollingIntevalMillis = 2000L) {
        return pollSidWhilePending(pollingIntevalMillis) {
            Requests.pollSid(flow, flow.loginService.sidWeb2AppPollUrl, queryParams)
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

    static Response initSidDeviceLinkMockAuth(Flow flow, SidAccount account, String deviceLink) {
        initSidDeviceLinkMockAuth(flow, account, deviceLink, null)
    }

    @Step("Start authentication in device link mock")
    static Response initSidDeviceLinkMockAuth(Flow flow, SidAccount account, String deviceLink, String altCallbackUrl) {
        Map mockRequest = [
                documentNumber: account.documentNumber,
                deviceLink    : deviceLink
        ]
        if (Utils.parseQueryParams(deviceLink).deviceLinkType == "Web2App") {
            String cookie = flow.cookieFilter.cookieStore.cookies
                    .find { it.name == "__Host-SESSION" }
                    ?.value
                    ?.with { "__Host-SESSION=$it" }

            mockRequest.browserCookie = cookie
            mockRequest.disableCallbackGetRequest = true

            // without it the mock uses the callback URL TARA sent to Smart-ID at session init
            // (by default flow.loginService.sidWeb2AppCallbackUrl)
            if (altCallbackUrl) {
                mockRequest.replacementInitialCallbackUrl = altCallbackUrl
            }
        }

        Response response = Requests.postDeviceLinkToMock(mockRequest)
        response.then().statusCode(HttpStatus.SC_OK)
        return response
    }

    @Step("Polling Smart-ID mock for callback URL")
    static Map<String, String> pollSidMockForCallbackUrl(String sessionToken) {
        PollingConditions conditions = new PollingConditions(timeout: 3, delay: 0.1)
        Response response = null

        conditions.eventually {
            response = Requests.get(ConfigHolder.testConf.deviceLinkMockUrl(), "/callback-url/" + sessionToken)
            assert response.statusCode() == HttpStatus.SC_OK
        }
        return response.as(Map)
    }

    @Step("Perform device-link mock flow until callback")
    static String sidMockAuthAndCallback(Flow flow, SidAccount account, String deviceLink) {
        initSidDeviceLinkMockAuth(flow, account, deviceLink)
        Map deviceLinkParams = Utils.parseQueryParams(deviceLink)
        Map mockResponse = pollSidMockForCallbackUrl(deviceLinkParams.sessionToken)
        Requests.performCallback(mockResponse).then().statusCode(HttpStatus.SC_OK)
        return mockResponse.callbackUrl
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

    static Map sidWeb2AppCallbackPollParams(flow, String callbackUrl) {
        Map callbackUrlParams = Utils.parseQueryParams(callbackUrl)
        [_csrf                : flow.csrf,
         value                : callbackUrlParams.value,
         sessionSecretDigest  : callbackUrlParams.sessionSecretDigest,
         userChallengeVerifier: callbackUrlParams.userChallengeVerifier
        ]
    }
}
