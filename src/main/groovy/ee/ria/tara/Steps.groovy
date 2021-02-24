package ee.ria.tara

import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.JOSEException
import com.nimbusds.jwt.SignedJWT
import io.qameta.allure.Allure
import io.qameta.allure.Step
import io.restassured.response.Response
import org.hamcrest.Matchers
import org.spockframework.lang.Wildcard

import java.text.ParseException

import static org.hamcrest.CoreMatchers.is
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.equalTo
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat

class Steps {

    @Step("Initialize authentication sequence in OIDC service with params")
    static Response startAuthenticationInOidcWithParams(Flow flow, Map<String, String> paramsMap) {
        Response initSession = Requests.getRequestWithParams(flow, flow.oidcService.fullAuthenticationRequestUrl, paramsMap, Collections.emptyMap())
        String authCookie = initSession.getCookie("oauth2_authentication_csrf")
        Utils.setParameter(flow.oidcService.cookies, "oauth2_authentication_csrf", authCookie)
        flow.setLoginChallenge(Utils.getParamValueFromResponseHeader(initSession, "login_challenge"))
        return initSession
    }

    @Step("Initialize authentication sequence in OIDC service with defaults")
    static Response startAuthenticationInOidc(Flow flow) {
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        assertEquals("Correct HTTP status code is returned", 302, initOIDCServiceSession.statusCode())
        return initOIDCServiceSession
    }

    @Step("Initialize authentication sequence in login service")
    static Response createLoginSession(Flow flow, Response response) {
        Response initLogin = followRedirect(flow, response)
        flow.setSessionId(initLogin.getCookie("SESSION"))
        if (initLogin.body().prettyPrint().contains("_csrf")) { // TARA2-121
            flow.setCsrf(initLogin.body().htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        }
        return initLogin
    }

    @Step("Start authentication in TARA and follow redirects")
    static Response startAuthenticationInTara(Flow flow, String scopeList = "openid", String locale = "et", boolean checkStatusCode = true) {
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, scopeList, locale)
        Response initOIDCServiceSession = startAuthenticationInOidcWithParams(flow, paramsMap)
        Response initLoginSession = createLoginSession(flow, initOIDCServiceSession)
        if (checkStatusCode) {
            assertEquals("Correct HTTP status code is returned", 200, initLoginSession.statusCode())
        }
        return initLoginSession
    }

    @Step("Initialize Mobile-ID authentication session")
    static Response initMidAuthSession(Flow flow, String sessionId
                                       , Object idCode, Object telephoneNumber
                                       , Map additionalParamsMap = Collections.emptyMap()) {
        LinkedHashMap<String, String> formParamsMap = (LinkedHashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "_csrf", flow.csrf)
        if (!(idCode instanceof Wildcard)) {
            Utils.setParameter(formParamsMap, "idCode", idCode)
        }
        if (!(telephoneNumber instanceof Wildcard)) {
            Utils.setParameter(formParamsMap, "telephoneNumber", telephoneNumber)
        }
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookieMap, "SESSION", sessionId)
        return Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullMidInitUrl, cookieMap, formParamsMap, additionalParamsMap)
    }

    @Step("Polling Mobile-ID authentication response")
    static Response pollMidResponse(Flow flow) {
        int counter = 0
        Response response = null
        while (counter < 12) {
            sleep(2000L)
            response = Requests.pollMid(flow)
            if (response.body().jsonPath().get("status") != "PENDING") {
                break
            }
            ++counter
        }
        return response
    }

    @Step("Authenticate with Mobile-ID")
    static Response authenticateWithMid(Flow flow, String idCode, String phoneNo) {
        Response midInit = Requests.startMidAuthentication(flow, idCode, phoneNo)
        assertEquals("Correct HTTP status code is returned", 200, midInit.statusCode())
        Response midPollResult = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, midPollResult.statusCode())
        assertThat(midPollResult.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 302, acceptResponse.statusCode())

        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        assertEquals("Correct HTTP status code is returned", 302, oidcServiceResponse.statusCode())

        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)

        return consentResponse
    }

    @Step("Authenticate with Smart-ID")
    static Response authenticateWithSid(Flow flow, String idCode) {
        Response sidInit = initSidAuthSession(flow, flow.sessionId, idCode, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, sidInit.statusCode())
        Response sidPollResult = pollSidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, sidPollResult.statusCode())
        assertThat(sidPollResult.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 302, acceptResponse.statusCode())

        Response oidcServiceResponse = getOAuthCookies(flow, acceptResponse)
        assertEquals("Correct HTTP status code is returned", 302, oidcServiceResponse.statusCode())

        Response consentResponse = followRedirectWithSessionId(flow, oidcServiceResponse)
        assertEquals("Correct HTTP status code is returned", 200, consentResponse.statusCode())
        return consentResponse
    }

    @Step("Authenticate with ID-Card")
    static Response authenticateWithIdCard(Flow flow, String certificateFileName) {
        String certificate = Utils.getCertificateAsString(certificateFileName)
        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(headersMap, "XCLIENTCERTIFICATE", certificate)
        Response response = Requests.idCardAuthentication(flow, headersMap)
        assertThat("Correct response", response.body().jsonPath().get("status").toString(), equalTo("COMPLETED"))

        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 302, acceptResponse.statusCode())
        Response oidcServiceResponse = getOAuthCookies(flow, acceptResponse)
        assertEquals("Correct HTTP status code is returned", 302, oidcServiceResponse.statusCode())

        Response consentResponse = followRedirectWithSessionId(flow, oidcServiceResponse)

        return consentResponse
    }

    @Step("Initialize Smart-ID authentication session")
    static Response initSidAuthSession(Flow flow, String sessionId
                                       , Object idCode
                                       , Map additionalParamsMap = Collections.emptyMap()) {
        LinkedHashMap<String, String> formParamsMap = (LinkedHashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "_csrf", flow.csrf)
        if (!(idCode instanceof Wildcard)) {
            Utils.setParameter(formParamsMap, "idCode", idCode)
        }
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookieMap, "SESSION", sessionId)
        return Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullSidInitUrl, cookieMap, formParamsMap, additionalParamsMap)
    }

    @Step("Polling Smart-ID authentication response")
    static Response pollSidResponse(Flow flow) {
        int counter = 0
        Response response = null
        while (counter < 20) {
            response = Requests.pollSid(flow)
            if (response.body().jsonPath().get("status") != "PENDING") {
                break
            }
            ++counter
            sleep(2000L)
        }
        return response
    }

    @Step("Initialize Eidas authentication session")
    static Response initEidasAuthSession(Flow flow, String sessionId
                                       , Object country
                                       , Map additionalParamsMap = Collections.emptyMap()) {
        LinkedHashMap<String, String> queryParamsMap = (LinkedHashMap) Collections.emptyMap()
        if (!(country instanceof Wildcard)) {
            Utils.setParameter(queryParamsMap, "country", country)
        }
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookieMap, "SESSION", sessionId)
        return Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullEidasInitUrl, cookieMap, queryParamsMap, additionalParamsMap)
    }

    @Step("Eidas service provider request")
    static Response eidasServiceProviderRequest(Flow flow, String url, String relayState, String samlRequest, String country = "CA") {
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "country", country)
        Utils.setParameter(formParamsMap, "RelayState", relayState)
        Utils.setParameter(formParamsMap, "SAMLRequest", samlRequest)
        Response serviceProviderResponse = Requests.postRequestWithParams(flow, url, formParamsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, serviceProviderResponse.statusCode())
        return serviceProviderResponse
    }

    @Step("Eidas specific connector request")
    static Response eidasSpecificConnectorRequest(Flow flow, Response response) {
        String specificConnectorUrl = response.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action")
        String token = response.body().htmlPath().getString("**.find { input -> input.@name == 'token' }.@value")
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "token", token)
        Response serviceProviderResponse = Requests.postRequestWithParams(flow, specificConnectorUrl, formParamsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, serviceProviderResponse.statusCode())
        return serviceProviderResponse
    }

    @Step("Eidas colleague request")
    static Response eidasColleagueRequest(Flow flow, Response response) {
        String colleagueRequestUrl = response.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action")
        String samlRequest = response.body().htmlPath().getString("**.find { input -> input.@id == 'noScriptSAMLRequest' }.@value")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "SAMLRequest", samlRequest)
        Response colleagueResponse = Requests.postRequestWithParams(flow, colleagueRequestUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, colleagueResponse.statusCode())
        return colleagueResponse
    }

    @Step("Eidas proxy service request")
    static Response eidasProxyServiceRequest(Flow flow, String endpointUrl, String token) {
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "token", token)
        Response proxyServiceResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, proxyServiceResponse.statusCode())
        return proxyServiceResponse
    }

    @Step("Eidas User gives consent for redirection to iDP")
    static Response eidasIdpRequest(Flow flow, Response response) {
        String endpointUrl = response.body().htmlPath().getString("**.find { it.@name == 'redirectForm' }.@action")
        String smsspRequest = response.body().htmlPath().getString("**.find { input -> input.@id == 'SMSSPRequest' }.@value")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "SMSSPRequest", smsspRequest)
        Response idpResponse =  Requests.postRequestWithParams(flow, endpointUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, idpResponse.statusCode())
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
        assertEquals("Correct HTTP status code is returned", 200, authorizationRequest.statusCode())
        return authorizationRequest
    }

    @Step("Eidas iDP authorization response")
    static Response eidasIdpAuthorizationResponse(Flow flow, Response response) {
        String endpointUrl = response.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String smsspTokenResponse = response.body().htmlPath().get("**.find {it.@id == 'SMSSPResponseNoJS'}.@value")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "SMSSPResponse", smsspTokenResponse)
        Response authorizationResponse =  Requests.postRequestWithParams(flow, endpointUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, authorizationResponse.statusCode())
        return authorizationResponse
    }

    @Step("Eidas confirm consent")
    static Response eidasConfirmConsent(Flow flow, String binaryLightToken) {
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "binaryLightToken", binaryLightToken)
        Response consentResponse =  Requests.postRequestWithParams(flow, flow.foreignProxyService.fullConsentUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, consentResponse.statusCode())
        return consentResponse
    }

    @Step("Eidas colleague response")
    static Response eidasColleagueResponse(Flow flow, Response response) {
        String endpointUrl = response.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String samlResponse = response.body().htmlPath().get("**.find {it.@id == 'ColleagueResponse_SAMLResponse'}.@value")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "SAMLResponse", samlResponse)
        Response colleagueResponse =  Requests.postRequestWithParams(flow, endpointUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, colleagueResponse.statusCode())
        return colleagueResponse
    }

    @Step("Continue authentication on abroad")
    static Response continueEidasAuthenticationFlow(Flow flow, String idpUsername, idpPassword, String eidasloa) {
        Response serviceProviderResponse = eidasServiceProviderRequest(flow, flow.nextEndpoint, flow.relayState, flow.requestMessage)
        Response specificconnectorResponse = eidasSpecificConnectorRequest(flow, serviceProviderResponse)
        Response colleagueResponse = eidasColleagueRequest(flow, specificconnectorResponse)
        String endpointUrl = colleagueResponse.body().htmlPath().getString("**.find { it.@id == 'redirectForm' }.@action")
        String token = colleagueResponse.body().htmlPath().getString("**.find { it.@id == 'token' }.@value")
        Response eidasProxyResponse = eidasProxyServiceRequest(flow, endpointUrl, token)

        Response initIdpResponse = eidasIdpRequest(flow, eidasProxyResponse)
        Response authorizationRequest = eidasIdpAuthorizationRequest(flow, initIdpResponse, idpUsername, idpPassword, eidasloa)
        Response authorizationResponse = eidasIdpAuthorizationResponse(flow, authorizationRequest)
        String binaryLightToken = authorizationResponse.body().htmlPath().get("**.find {it.@id == 'binaryLightToken'}.@value")
        Response consentResponse = eidasConfirmConsent(flow, binaryLightToken)
        String endpointUrl2 = consentResponse.body().htmlPath().getString("**.find { it.@id == 'redirectForm' }.@action")
        String token2 = consentResponse.body().htmlPath().getString("**.find { it.@id == 'token' }.@value")
        Response eidasProxyResponse2 = eidasProxyServiceRequest(flow, endpointUrl2, token2)
        return eidasColleagueResponse(flow, eidasProxyResponse2)
    }

    @Step("Eidas authorization response")
    static Response getAuthorizationResponseFromEidas(Flow flow, Response response) {
        String endpointUrl = response.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String lightToken = response.body().htmlPath().get("**.find {it.@id == 'token'}.@value")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "token", lightToken)
        Response authorizationResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, authorizationResponse.statusCode())
        return authorizationResponse
    }

    @Step("Eidas redirect authorization response to service provider")
    static Response eidasRedirectAuthorizationResponse(Flow flow, Response response) {
        String endpointUrl = response.body().htmlPath().get("**.find {it.@method == 'post'}.@action")
        String samlResponse = response.body().htmlPath().get("**.find {it.@name == 'SAMLResponse'}.@value")
        String relayState = response.body().htmlPath().get("**.find {it.@name == 'RelayState'}.@value")
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "SAMLResponse" , samlResponse)
        Utils.setParameter(paramsMap, "RelayState", relayState)
        Response redirectionResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, redirectionResponse.statusCode())
        return redirectionResponse
    }

    @Step("Eidas accept authorization result")
    static Response eidasAcceptAuthorizationResult(flow, Response response) {
        flow.setCsrf(response.body().htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
    }

    @Step("Getting OAuth2 cookies")
    static Response getOAuthCookies(flow, Response response) {
        Response oidcServiceResponse = followRedirectWithCookies(flow, response, flow.oidcService.cookies)
        String oauthConsentCookie = oidcServiceResponse.getCookie("oauth2_consent_csrf")
        // String oauthSessionCookie = oidcServiceResponse.getCookie("oauth2_authentication_session")
        // Utils.setParameter(flow.oidcService.cookies, "oauth2_authentication_session", oauthSessionCookie)
        Utils.setParameter(flow.oidcService.cookies, "oauth2_consent_csrf", oauthConsentCookie)
        return oidcServiceResponse
    }

    @Step("Initialize authentication session")
    static Response initLoginSession(Flow flow, Response response, Map<String, String> additionalParamsMap) {
        String location = response.then().extract().response().getHeader("location")
        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        HashMap<String, String> paramMap = (HashMap) Collections.emptyMap()
        Response initResponse = Requests.getRequestWithCookiesAndParams(flow, location, cookiesMap, paramMap, additionalParamsMap)
        flow.setSessionId(initResponse.getCookie("SESSION"))
        flow.setCsrf(initResponse.body().htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        return initResponse
    }

    @Step("Follow redirect")
    static Response followRedirect(Flow flow, Response response) {
        String location = response.then().extract().response().getHeader("location")
        return Requests.followRedirect(flow, location)
    }

    @Step("Follow redirect with cookies")
    static Response followRedirectWithCookies(Flow flow, Response response, Map cookies) {
        String location = response.then().extract().response().getHeader("location")
        return Requests.followRedirectWithCookie(flow, location, cookies)
    }

    @Step("Follow redirect with session id")
    static Response followRedirectWithSessionId(Flow flow, Response response) {
        String location = response.then().extract().response().getHeader("location")
        return Requests.getRequestWithSessionId(flow, location)
    }

    @Step("Confirm or reject consent")
    static Response submitConsent(Flow flow, boolean consentGiven) {
        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookiesMap, "SESSION", flow.sessionId)
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "consent_given", consentGiven)
        Utils.setParameter(formParamsMap, "_csrf", flow.csrf)
        Response consentConfirmResponse = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullConsentConfirmUrl, cookiesMap, formParamsMap, Collections.emptyMap())
        return consentConfirmResponse
    }

    @Step("Confirm or reject consent and finish authentication process")
    static Response submitConsentAndFollowRedirects(Flow flow, boolean consentGiven, Response consentResponse) {
        if (consentResponse.getStatusCode() == 200) {
            consentResponse = Steps.submitConsent(flow, consentGiven)
            assertEquals("Correct HTTP status code is returned", 302, consentResponse.statusCode())

        }
        return Steps.followRedirectWithCookies(flow, consentResponse, flow.oidcService.cookies)
    }

    @Step("Get identity token")
    static Response getIdentityTokenResponse(Flow flow, Response response) {
        String authorizationCode = Utils.getParamValueFromResponseHeader(response, "code")
        return Requests.getWebToken(flow, authorizationCode)
    }

    @Step("verify token")
    static SignedJWT verifyTokenAndReturnSignedJwtObject(Flow flow, String token) throws ParseException, JOSEException, IOException {
        SignedJWT signedJWT = SignedJWT.parse(token)
        //TODO: single attachment
        addJsonAttachment("Header", signedJWT.getHeader().toString())
        addJsonAttachment("Payload", signedJWT.getJWTClaimsSet().toString())
        try {
            Allure.link("View Token in jwt.io", new io.qameta.allure.model.Link().toString(),
                    "https://jwt.io/#debugger-io?token=" + token)
        } catch (Exception e) {
            //NullPointerException when running test from IntelliJ
        }
        assertThat("Token Signature is not valid!", OpenIdUtils.isTokenSignatureValid(flow.jwkSet, signedJWT), is(true))
        assertThat(signedJWT.getJWTClaimsSet().getAudience().get(0), equalTo(flow.oidcClient.clientId))
        assertThat(signedJWT.getJWTClaimsSet().getIssuer(), equalTo(flow.openIdServiceConfiguration.get("issuer")))
        Date date = new Date()
        assertThat("Expected current: " + date + " to be before exp: " + signedJWT.getJWTClaimsSet().getExpirationTime(), date.before(signedJWT.getJWTClaimsSet().getExpirationTime()), is(true))
        // TODO Etapp 4
        // assertThat("Expected current: " + date + " to be after nbf: " + signedJWT.getJWTClaimsSet().getNotBeforeTime(), date.after(signedJWT.getJWTClaimsSet().getNotBeforeTime()), is(true))
        if (!flow.getNonce().isEmpty()) {
            assertThat(signedJWT.getJWTClaimsSet().getStringClaim("nonce"), equalTo(flow.getNonce()))
        }
        // TARA2-182
        // assertThat(signedJWT.getJWTClaimsSet().getStringClaim("state"), equalTo(flow.getState()))
        return signedJWT
    }

    @Step("verify response headers")
    static void verifyResponseHeaders(Response response) {
        assertThat(response.getHeader("X-Frame-Options"), equalTo("DENY"))
        String policyString = "connect-src 'self'; default-src 'none'; font-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; block-all-mixed-content"
        assertThat(response.getHeader("Content-Security-Policy"), equalTo(policyString))
        assertThat(response.getHeader("Strict-Transport-Security"), containsString("max-age=16070400"))
        assertThat(response.getHeader("Strict-Transport-Security"), containsString("includeSubDomains"))
        assertThat(response.getHeader("Cache-Control"), equalTo("no-cache, no-store, max-age=0, must-revalidate"))
        assertThat(response.getHeader("X-Content-Type-Options"), equalTo("nosniff"))
        assertThat(response.getHeader("X-XSS-Protection"), equalTo("1; mode=block"))
    }

    @Step("Get user info response with header parameter")
    static Response getUserInfoResponseWithHeaderParam(Flow flow, String requestType, String accessToken) {
        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        headersMap.put("Authorization", "Bearer " +accessToken)
        return Requests.getUserInfoWithHeaderParam (flow, requestType, headersMap)
    }

    @Step("Get user info response with query parameter")
    static Response getUserInfoResponseWithQueryParam(Flow flow, String requestType, String accessToken) {
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        paramsMap.put("access_token", accessToken)
        return Requests.getUserInfoWithQueryParam (flow, requestType, paramsMap)
    }

    private static void addJsonAttachment(String name, String json) throws IOException {
        ObjectMapper mapper = new ObjectMapper()
        Object jsonObject = mapper.readValue(json, Object.class)
        String prettyJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObject)
        Allure.addAttachment(name, "application/json", prettyJson, "json")
    }
}
