package ee.ria.tara

import io.qameta.allure.Step
import io.restassured.response.Response

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is

class EidasSteps {
    @Step("Initialize Eidas authentication session")
    static Response initEidasAuthSession(Flow flow, Object country) {
        Map queryParamsMap = [country: country,
                              _csrf  : flow.csrf]
        Response response = Requests.postRequestWithParams(flow, flow.loginService.fullEidasInitUrl, queryParamsMap)
        if (response.statusCode.toInteger() == 200) {
            flow.setNextEndpoint(response.htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
            flow.setRelayState(response.htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
            flow.setRequestMessage(response.htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        }
        return response
    }

    @Step("Eidas service provider request")
    static Response eidasServiceProviderRequest(Flow flow, String url, String relayState, String samlRequest, String country = "CA") {
        Map formParamsMap = [
                "country"    : country,
                "RelayState" : relayState,
                "SAMLRequest": samlRequest]

        Response serviceProviderResponse = Requests.postRequestWithParams(flow, url, formParamsMap)
        assertThat("Correct HTTP status code", serviceProviderResponse.statusCode, is(200))
        return serviceProviderResponse
    }

    @Step("Eidas specific connector request")
    static Response eidasSpecificConnectorRequest(Flow flow, Response response) {
        String specificConnectorUrl = response.htmlPath().getString("**.find { form -> form.@method == 'post' }.@action")
        String token = response.htmlPath().getString("**.find { input -> input.@name == 'token' }.@value")
        Map formParamsMap = ["token": token]
        Response serviceProviderResponse = Requests.postRequestWithParams(flow, specificConnectorUrl, formParamsMap)
        assertThat("Correct HTTP status code", serviceProviderResponse.statusCode, is(200))
        return serviceProviderResponse
    }

    @Step("Eidas colleague request")
    static Response eidasColleagueRequest(Flow flow, Response response) {
        String colleagueRequestUrl = response.htmlPath().getString("**.find { form -> form.@method == 'post' }.@action")
        String samlRequest = response.htmlPath().getString("**.find { input -> input.@id == 'noScriptSAMLRequest' }.@value")
        Map paramsMap = ["SAMLRequest": samlRequest]
        Response colleagueResponse = Requests.postRequestWithParams(flow, colleagueRequestUrl, paramsMap)
        assertThat("Correct HTTP status code", colleagueResponse.statusCode, is(200))
        return colleagueResponse
    }

    @Step("Eidas proxy service request")
    static Response eidasProxyServiceRequest(Flow flow, String endpointUrl, String token) {
        Map paramsMap = [token: token]
        Response proxyServiceResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap)
        assertThat("Correct HTTP status code", proxyServiceResponse.statusCode, is(200))
        return proxyServiceResponse
    }

    @Step("Eidas User gives consent for redirection to iDP")
    static Response eidasIdpRequest(Flow flow, Response response) {
        String endpointUrl = response.htmlPath().getString("**.find { it.@name == 'redirectForm' }.@action")
        String smsspRequest = response.htmlPath().getString("**.find { input -> input.@id == 'SMSSPRequest' }.@value")
        Map paramsMap = ["SMSSPRequest": smsspRequest]
        Response idpResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap)
        assertThat("Correct HTTP status code", idpResponse.statusCode, is(200))
        return idpResponse
    }

    @Step("Eidas iDP authorization request")
    static Response eidasIdpAuthorizationRequest(Flow flow, Response response, String idpUsername, idpPassword, String eidasloa) {
        String callbackUrl = response.htmlPath().getString("**.find { it.@name == 'callback' }.@value")
        String smsspToken = response.htmlPath().get("**.find {it.@name == 'smsspToken'}.@value")
        String smsspTokenRequestJson = response.htmlPath().get("**.find {it.@id == 'jSonRequestDecoded'}")
        Map paramsMap = [
                "smsspToken"        : smsspToken,
                "username"          : idpUsername,
                "password"          : idpPassword,
                "eidasloa"          : eidasloa,
                "eidasnameid"       : "persistent",
                "callback"          : callbackUrl,
                "jSonRequestDecoded": smsspTokenRequestJson]
        Response authorizationRequest = Requests.postRequestWithParams(flow, flow.foreignIdpProvider.fullResponseUrl, paramsMap)
        assertThat("Correct HTTP status code", authorizationRequest.statusCode, is(200))
        return authorizationRequest
    }

    @Step("Eidas iDP authorization response")
    static Response eidasIdpAuthorizationResponse(Flow flow, Response response) {
        String endpointUrl = response.htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String smsspTokenResponse = response.htmlPath().get("**.find {it.@id == 'SMSSPResponseNoJS'}.@value")
        Map paramsMap = ["SMSSPResponse": smsspTokenResponse]
        Response authorizationResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap)
        assertThat("Correct HTTP status code", authorizationResponse.statusCode, is(200))
        return authorizationResponse
    }

    @Step("Eidas confirm consent")
    static Response eidasConfirmConsent(Flow flow, String binaryLightToken) {
        Map paramsMap = ["binaryLightToken": binaryLightToken]
        Response consentResponse = Requests.postRequestWithParams(flow, flow.foreignProxyService.fullConsentUrl, paramsMap)
        assertThat("Correct HTTP status code", consentResponse.statusCode, is(200))
        return consentResponse
    }

    @Step("Eidas colleague response")
    static Response eidasColleagueResponse(Flow flow, Response response) {
        String endpointUrl = response.htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String samlResponse = response.htmlPath().get("**.find {it.@name == 'SAMLResponse'}.@value")
        Map paramsMap = ["SAMLResponse": samlResponse]
        Response colleagueResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap)
        assertThat("Correct HTTP status code", colleagueResponse.statusCode, is(200))
        return colleagueResponse
    }

    @Step("Continue authentication on abroad")
    static Response continueEidasAuthenticationFlow(Flow flow, String idpUsername, idpPassword, String eidasloa) {
        Response authorizationResponse = continueEidasFlow(flow, idpUsername, idpPassword, eidasloa)
        String binaryLightToken = authorizationResponse.htmlPath().get("**.find {it.@id == 'binaryLightToken'}.@value")
        Response consentResponse = eidasConfirmConsent(flow, binaryLightToken)
        String endpointUrl2 = consentResponse.htmlPath().getString("**.find { it.@id == 'redirectForm' }.@action")
        String token2 = consentResponse.htmlPath().getString("**.find { it.@id == 'token' }.@value")
        Response eidasProxyResponse2 = eidasProxyServiceRequest(flow, endpointUrl2, token2)
        return eidasColleagueResponse(flow, eidasProxyResponse2)
    }

    @Step("Continue Eidas flow")
    static Response continueEidasFlow(Flow flow, String idpUsername, idpPassword, String eidasloa) {
        Response serviceProviderResponse = eidasServiceProviderRequest(flow, flow.nextEndpoint, flow.relayState, flow.requestMessage)
        Response specificConnectorResponse = eidasSpecificConnectorRequest(flow, serviceProviderResponse)
        Response colleagueResponse = eidasColleagueRequest(flow, specificConnectorResponse)
        String endpointUrl = colleagueResponse.htmlPath().getString("**.find { it.@id == 'redirectForm' }.@action")
        String token = colleagueResponse.htmlPath().getString("**.find { it.@id == 'token' }.@value")
        Response eidasProxyResponse = eidasProxyServiceRequest(flow, endpointUrl, token)

        Response initIdpResponse = eidasIdpRequest(flow, eidasProxyResponse)
        Response authorizationRequest = eidasIdpAuthorizationRequest(flow, initIdpResponse, idpUsername, idpPassword, eidasloa)
        Response authorizationResponse = eidasIdpAuthorizationResponse(flow, authorizationRequest)
        return authorizationResponse
    }

    @Step("Eidas authorization response")
    static Response getAuthorizationResponseFromEidas(Flow flow, Response response) {
        String endpointUrl = response.htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String lightToken = response.htmlPath().get("**.find {it.@id == 'token'}.@value")
        Map paramsMap = ["token": lightToken]
        Response authorizationResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap)
        assertThat("Correct HTTP status code", authorizationResponse.statusCode, is(200))
        flow.setNextEndpoint(authorizationResponse.htmlPath().getString("**.find {it.@method == 'post'}.@action"))
        flow.setResponseMessage(authorizationResponse.htmlPath().getString("**.find {it.@name == 'SAMLResponse'}.@value"))
        flow.setRelayState(authorizationResponse.htmlPath().getString("**.find {it.@name == 'RelayState'}.@value"))
        return authorizationResponse
    }

    @Step("Eidas redirect authorization response to service provider")
    static Response eidasRedirectAuthorizationResponse(Flow flow, Response response, boolean checkStatusCode = true) {
        String endpointUrl = response.htmlPath().get("**.find {it.@method == 'post'}.@action")
        String samlResponse = response.htmlPath().get("**.find {it.@name == 'SAMLResponse'}.@value")
        String relayState = response.htmlPath().get("**.find {it.@name == 'RelayState'}.@value")
        Map paramsMap = [
                "SAMLResponse": samlResponse,
                "RelayState"  : relayState]
        Response redirectionResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap)
        if (checkStatusCode) {
            assertThat("Correct HTTP status code", redirectionResponse.statusCode, is(200))
        }
        return redirectionResponse
    }

    @Step("Eidas accept authorization result")
    static Response eidasAcceptAuthorizationResult(Flow flow, Response response) {
        flow.setCsrf(response.htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        return Requests.postRequestWithParams(flow, flow.loginService.fullAuthAcceptUrl)
    }

}
