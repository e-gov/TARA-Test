package ee.ria.tara.step

import ee.ria.tara.Flow
import ee.ria.tara.Requests
import ee.ria.tara.Steps
import ee.ria.tara.Utils
import io.qameta.allure.Step
import org.json.JSONObject

class WebEidSteps {

    @Step("Authentication flow up to Web eID authentication token generation")
    static JSONObject authenticationFlowToWebEidParams(
            Flow flow,
            String keyStore = "src/test/resources/EE38001085718_auth_EC_TEST_of_ESTEID2018.p12") {
        Steps.startAuthenticationInTara(flow)
        String nonce = Requests.postRequest(flow, flow.loginService.fullWebEidInitUrl).jsonPath().get("nonce")
        String signAuthValue = Utils.signAuthenticationValue(flow, flow.loginService.baseUrl, nonce, keyStore)
        return Utils.getWebEidAuthTokenParameters(flow, signAuthValue)
    }

    @Step("Authentication flow up to Web eID authentication token generation, from in-memory keystore")
    static JSONObject authenticationFlowToWebEidParams(Flow flow, byte[] p12Bytes) {
        Steps.startAuthenticationInTara(flow)
        String nonce = Requests.postRequest(flow, flow.loginService.fullWebEidInitUrl).jsonPath().get("nonce")
        String signAuthValue = Utils.signAuthenticationValue(flow, flow.loginService.baseUrl, nonce, p12Bytes)
        return Utils.getWebEidAuthTokenParameters(flow, signAuthValue)
    }
}
