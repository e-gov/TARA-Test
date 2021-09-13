package ee.ria.tara

import io.qameta.allure.Step
import io.restassured.response.Response
import org.spockframework.lang.Wildcard

import static org.junit.jupiter.api.Assertions.assertEquals

class EidasSteps {
    @Step("Initialize Eidas authentication session")
    static Response initEidasAuthSession(Flow flow, String sessionId
                                         , Object country
                                         , Map additionalParamsMap = Collections.emptyMap()) {
        LinkedHashMap<String, String> queryParamsMap = (LinkedHashMap) Collections.emptyMap()
        if (!(country instanceof Wildcard)) {
            Utils.setParameter(queryParamsMap, "country", country)
        }
        Utils.setParameter(queryParamsMap, "_csrf", flow.csrf)
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookieMap, "SESSION", sessionId)
        return Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullEidasInitUrl, cookieMap, queryParamsMap, additionalParamsMap)
    }

    @Step("Eidas service provider request")
    static Response eidasServiceProviderRequest(Flow flow, String url, String relayState, String samlRequest, String country = "CA") {
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "country", country)
        Utils.setParameter(formParamsMap, "RelayState", relayState)
        Utils.setParameter(formParamsMap, "SAMLRequest", samlRequest)
        Response serviceProviderResponse = Requests.postRequestWithParams(flow, url, formParamsMap, Collections.emptyMap())
        assertEquals(200, serviceProviderResponse.statusCode(), "Correct HTTP status code is returned")
        return serviceProviderResponse
    }

    @Step("Eidas specific connector request")
    static Response eidasSpecificConnectorRequest(Flow flow, Response response) {
        String specificConnectorUrl = response.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action")
        String token = response.body().htmlPath().getString("**.find { input -> input.@name == 'token' }.@value")
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "token", token)
        Response serviceProviderResponse = Requests.postRequestWithParams(flow, specificConnectorUrl, formParamsMap, Collections.emptyMap())
        assertEquals(200, serviceProviderResponse.statusCode(), "Correct HTTP status code is returned")
        return serviceProviderResponse
    }

    @Step("Eidas colleague request")
    static Response eidasColleagueRequest(Flow flow, Response response) {
        String colleagueRequestUrl = response.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action")
        String samlRequest = response.body().htmlPath().getString("**.find { input -> input.@id == 'noScriptSAMLRequest' }.@value")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "SAMLRequest", samlRequest)
        Response colleagueResponse = Requests.postRequestWithParams(flow, colleagueRequestUrl, paramsMap, Collections.emptyMap())
        assertEquals(200, colleagueResponse.statusCode(), "Correct HTTP status code is returned")
        return colleagueResponse
    }

    @Step("Eidas proxy service request")
    static Response eidasProxyServiceRequest(Flow flow, String endpointUrl, String token) {
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "token", token)
        Response proxyServiceResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap, Collections.emptyMap())
        assertEquals(200, proxyServiceResponse.statusCode(), "Correct HTTP status code is returned")
        return proxyServiceResponse
    }

    @Step("Eidas User gives consent for redirection to iDP")
    static Response eidasIdpRequest(Flow flow, Response response) {
        String endpointUrl = response.body().htmlPath().getString("**.find { it.@name == 'redirectForm' }.@action")
        String smsspRequest = response.body().htmlPath().getString("**.find { input -> input.@id == 'SMSSPRequest' }.@value")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "SMSSPRequest", smsspRequest)
        Response idpResponse =  Requests.postRequestWithParams(flow, endpointUrl, paramsMap, Collections.emptyMap())
        assertEquals(200, idpResponse.statusCode(), "Correct HTTP status code is returned")
        return idpResponse
    }

    @Step("Eidas iDP authorization request")
    static Response eidasIdpAuthorizationRequest(flow, Response response, String idpUsername, idpPassword, String eidasloa) {
        String callbackUrl = response.body().htmlPath().getString("**.find { it.@name == 'callback' }.@value")
        String smsspToken = response.body().htmlPath().get("**.find {it.@name == 'smsspToken'}.@value")
        String smsspTokenRequestJson = response.body().htmlPath().get("**.find {it.@id == 'jSonRequestDecoded'}")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "smsspToken", smsspToken)
        Utils.setParameter(paramsMap, "username", idpUsername)
        Utils.setParameter(paramsMap, "password", idpPassword)
        Utils.setParameter(paramsMap, "eidasloa", eidasloa)
        Utils.setParameter(paramsMap, "eidasnameid", "persistent")
        Utils.setParameter(paramsMap, "callback", callbackUrl)
        Utils.setParameter(paramsMap, "jSonRequestDecoded", smsspTokenRequestJson)
        Response authorizationRequest =  Requests.postRequestWithParams(flow, flow.foreignIdpProvider.fullResponseUrl, paramsMap, Collections.emptyMap())
        assertEquals(200, authorizationRequest.statusCode(), "Correct HTTP status code is returned")
        return authorizationRequest
    }

    @Step("Eidas iDP authorization response")
    static Response eidasIdpAuthorizationResponse(Flow flow, Response response) {
        String endpointUrl = response.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String smsspTokenResponse = response.body().htmlPath().get("**.find {it.@id == 'SMSSPResponseNoJS'}.@value")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "SMSSPResponse", smsspTokenResponse)
        Response authorizationResponse =  Requests.postRequestWithParams(flow, endpointUrl, paramsMap, Collections.emptyMap())
        assertEquals(200, authorizationResponse.statusCode(), "Correct HTTP status code is returned")
        return authorizationResponse
    }

    @Step("Eidas confirm consent")
    static Response eidasConfirmConsent(Flow flow, String binaryLightToken) {
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "binaryLightToken", binaryLightToken)
        Response consentResponse =  Requests.postRequestWithParams(flow, flow.foreignProxyService.fullConsentUrl, paramsMap, Collections.emptyMap())
        assertEquals(200, consentResponse.statusCode(), "Correct HTTP status code is returned")
        return consentResponse
    }

    @Step("Eidas colleague response")
    static Response eidasColleagueResponse(Flow flow, Response response) {
        String endpointUrl = response.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String samlResponse = response.body().htmlPath().get("**.find {it.@name == 'SAMLResponse'}.@value")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "SAMLResponse", samlResponse)
        Response colleagueResponse =  Requests.postRequestWithParams(flow, endpointUrl, paramsMap, Collections.emptyMap())
        assertEquals(200, colleagueResponse.statusCode(), "Correct HTTP status code is returned")
        return colleagueResponse
    }

    @Step("Continue authentication on abroad")
    static Response continueEidasAuthenticationFlow(Flow flow, String idpUsername, idpPassword, String eidasloa) {
        Response authorizationResponse = continueEidasFlow(flow, idpUsername, idpPassword, eidasloa)
        String binaryLightToken = authorizationResponse.body().htmlPath().get("**.find {it.@id == 'binaryLightToken'}.@value")
        Response consentResponse = eidasConfirmConsent(flow, binaryLightToken)
        String endpointUrl2 = consentResponse.body().htmlPath().getString("**.find { it.@id == 'redirectForm' }.@action")
        String token2 = consentResponse.body().htmlPath().getString("**.find { it.@id == 'token' }.@value")
        Response eidasProxyResponse2 = eidasProxyServiceRequest(flow, endpointUrl2, token2)
        return eidasColleagueResponse(flow, eidasProxyResponse2)
    }

    @Step("Continue Eidas flow")
    static Response continueEidasFlow(Flow flow, String idpUsername, idpPassword, String eidasloa) {
        Response serviceProviderResponse = eidasServiceProviderRequest(flow, flow.nextEndpoint, flow.relayState, flow.requestMessage)
        Response specificconnectorResponse = eidasSpecificConnectorRequest(flow, serviceProviderResponse)
        Response colleagueResponse = eidasColleagueRequest(flow, specificconnectorResponse)
        String endpointUrl = colleagueResponse.body().htmlPath().getString("**.find { it.@id == 'redirectForm' }.@action")
        String token = colleagueResponse.body().htmlPath().getString("**.find { it.@id == 'token' }.@value")
        Response eidasProxyResponse = eidasProxyServiceRequest(flow, endpointUrl, token)

        Response initIdpResponse = eidasIdpRequest(flow, eidasProxyResponse)
        Response authorizationRequest = eidasIdpAuthorizationRequest(flow, initIdpResponse, idpUsername, idpPassword, eidasloa)
        Response authorizationResponse = eidasIdpAuthorizationResponse(flow, authorizationRequest)
        authorizationResponse
    }

    @Step("Eidas authorization response")
    static Response getAuthorizationResponseFromEidas(Flow flow, Response response) {
        String endpointUrl = response.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String lightToken = response.body().htmlPath().get("**.find {it.@id == 'token'}.@value")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "token", lightToken)
        Response authorizationResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap, Collections.emptyMap())
        assertEquals(200, authorizationResponse.statusCode(), "Correct HTTP status code is returned")
        return authorizationResponse
    }

    @Step("Eidas redirect authorization response to service provider")
    static Response eidasRedirectAuthorizationResponse(Flow flow, Response response, boolean checkStatusCode = true) {
        String endpointUrl = response.body().htmlPath().get("**.find {it.@method == 'post'}.@action")
        String samlResponse = response.body().htmlPath().get("**.find {it.@name == 'SAMLResponse'}.@value")
        String relayState = response.body().htmlPath().get("**.find {it.@name == 'RelayState'}.@value")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "SAMLResponse" , samlResponse)
        Utils.setParameter(paramsMap, "RelayState", relayState)
        Response redirectionResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap, Collections.emptyMap())
        if (checkStatusCode) {
            assertEquals(200, redirectionResponse.statusCode(), "Correct HTTP status code is returned")
        }
        return redirectionResponse
    }

    @Step("Eidas accept authorization result")
    static Response eidasAcceptAuthorizationResult(flow, Response response) {
        flow.setCsrf(response.body().htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        return Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
    }

}
