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
import static org.hamcrest.Matchers.equalTo
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat

class Steps {

    @Step("Create client authentication session")
    static Response createAuthenticationSession(Flow flow, String scopeList = "openid") {
        Response initAuthResponse = Requests.initAuthRequest(flow, scopeList)
        String taraClientCookie = initAuthResponse.getCookie("TARAClient")
        Utils.setParameter(flow.oidcClient.cookies,"TARAClient", taraClientCookie)
        flow.state = Utils.getParamValueFromResponseHeader(initAuthResponse, "state")
        flow.nonce = Utils.getParamValueFromResponseHeader(initAuthResponse, "nonce")
        return initAuthResponse
    }

    @Step("Create authentication session in oidc service")
    static Response createOIDCSession(Flow flow, Response response) {
        Response initSession = followRedirect(flow, response)
        String authCookie = initSession.getCookie("oauth2_authentication_csrf")
        Utils.setParameter(flow.oidcService.cookies,"oauth2_authentication_csrf", authCookie)
        flow.setLoginChallenge(Utils.getParamValueFromResponseHeader(initSession, "login_challenge"))
        return initSession
    }

    @Step("Create authentication session in oidc service with parameters")
    static Response createOIDCSessionWithParameters(Flow flow, Map<String, String> paramsMap) {
        Response initSession = Requests.getRequestWithParams(flow , flow.oidcService.fullAuthenticationRequestUrl, paramsMap, Collections.emptyMap())
        String authCookie = initSession.getCookie("oauth2_authentication_csrf")
        Utils.setParameter(flow.oidcService.cookies,"oauth2_authentication_csrf", authCookie)
        flow.setLoginChallenge(Utils.getParamValueFromResponseHeader(initSession, "login_challenge"))
        return initSession
    }

    @Step("Create login session")
    static Response createLoginSession(Flow flow, Response response) {
        Response initLogin = followRedirect(flow, response)
        flow.setSessionId(initLogin.getCookie("SESSION"))
        flow.setCsrf(initLogin.body().htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        return initLogin
    }

    @Step("Initialize Mobile-ID authentication session")
    static Response initMidAuthSession(Flow flow, String sessionId
                                       , Object idCode, Object telephoneNumber
                                       , Map additionalParamsMap = Collections.emptyMap()) {
        LinkedHashMap<String, String> formParamsMap = (LinkedHashMap)Collections.emptyMap()
        Utils.setParameter(formParamsMap, "_csrf", flow.csrf)
        if (!(idCode instanceof Wildcard)) {
            Utils.setParameter(formParamsMap, "idCode", idCode)
        }
        if (!(telephoneNumber instanceof Wildcard)) {
            Utils.setParameter(formParamsMap, "telephoneNumber", telephoneNumber)
        }
        HashMap<String, String> cookieMap = (HashMap)Collections.emptyMap()
        Utils.setParameter(cookieMap, "SESSION", sessionId)
        return Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullMidInitUrl, cookieMap, formParamsMap, additionalParamsMap)
    }

    @Step("Polling Mobile-ID authentication response")
    static Response pollMidResponse(Flow flow) {
        int counter = 0
        Response response = null
        while(counter < 10) {
            response = Requests.pollMid(flow)
            if( response.body().jsonPath().get("status") != "PENDING") {
                break
            }
            ++counter
            sleep(4000L)
        }
  //      if( response.body().jsonPath().get("status") == "COMPLETED" && response.getCookie("SESSION") != null) {
  //          flow.setSessionId(response.getCookie("SESSION"))
  //      }
        return response
    }

    @Step("Getting OAuth2 cookies")
    static Response getOAuthCookies(flow, Response response) {
        Response oidcServiceResponse = followRedirectWithCookies(flow, response, flow.oidcService.cookies)
        String oauthConsentCookie = oidcServiceResponse.getCookie("oauth2_consent_csrf")
        // String oauthSessionCookie = oidcServiceResponse.getCookie("oauth2_authentication_session")
        // Utils.setParameter(flow.oidcService.cookies, "oauth2_authentication_session", oauthSessionCookie)
        Utils.setParameter(flow.oidcService.cookies,"oauth2_consent_csrf", oauthConsentCookie)
        return oidcServiceResponse
    }

    @Step("Initialize authentication session")
    static Response initLoginSession(Flow flow, Response response, Map<String, String> additionalParamsMap) {
        String location = response.then().extract().response().getHeader("location")
        HashMap<String, String> cookiesMap = (HashMap)Collections.emptyMap()
        HashMap<String, String> paramMap = (HashMap)Collections.emptyMap()
        Response initResponse= Requests.getRequestWithCookiesAndParams(flow , location, cookiesMap, paramMap, additionalParamsMap)
        flow.setSessionId(initResponse.getCookie("SESSION"))
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

    @Step("Init person authentication session")
    static Response initAuthenticationSession(Flow flow, String scopeList = "openid") {
        Response initOIDCServiceSession = createSession(flow, scopeList)
        Response initLoginSession = createLoginSession(flow, initOIDCServiceSession)
        assertEquals("Correct HTTP status code is returned", 200, initLoginSession.statusCode())
        return initLoginSession
    }

    @Step("init auth session and authenticate with mobile-ID")
    static Response initAuthSessionAndAuthWithMobileID(Flow flow) {
        Response initClientAuthenticationSession = initAuthenticationSession(flow)
        Response oidcServiceResponse = authWithMobileID(flow)
        return oidcServiceResponse
    }

    @Step("authenticate with mobile-ID")
    static Response authWithMobileID(Flow flow, String idCode = "60001017716", String telephoneNumber = "69100366") {
        Response initMidAuthenticationSession = initMidAuthSession(flow, flow.sessionId, idCode, telephoneNumber, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, pollResponse.statusCode())
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 302, acceptResponse.statusCode())
        Response oidcServiceResponse = getOAuthCookies(flow, acceptResponse)
        assertEquals("Correct HTTP status code is returned", 302, oidcServiceResponse.statusCode())
        return oidcServiceResponse
    }

    @Step("Confirm or reject consent")
    static Response consentConfirmation(Flow flow, boolean consentGiven) {
        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(cookiesMap, "SESSION", flow.sessionId)
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "consent_given", consentGiven)
        Utils.setParameter(formParamsMap, "_csrf", flow.csrf)
        Response consentConfirmResponse = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullConsentConfirmUrl, cookiesMap, formParamsMap, Collections.emptyMap())
        return consentConfirmResponse
    }

    static Response createSession(Flow flow, String scopeList = "openid") {
        Response initClientAuthenticationSession = createAuthenticationSession(flow, scopeList)
        assertEquals("Correct HTTP status code is returned", 302, initClientAuthenticationSession.statusCode())
        Response initOIDCServiceSession = createOIDCSession(flow, initClientAuthenticationSession)
        assertEquals("Correct HTTP status code is returned", 302, initOIDCServiceSession.statusCode())
        return initOIDCServiceSession
    }

    @Step("get webtoken from OIDC service")
    static Response getWebTokenFromOidcService(Flow flow, Response response) {
        Response oidcServiceResponse2 = followRedirectWithCookies(flow, response, flow.oidcService.cookies)
        assertEquals("Correct HTTP status code is returned", 302, oidcServiceResponse2.statusCode())
        Response webTokenResponse = followRedirectWithCookies(flow, oidcServiceResponse2, flow.oidcClient.cookies)
        assertEquals("Correct HTTP status code is returned", 200, webTokenResponse.statusCode())
        return webTokenResponse
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
        assertThat(signedJWT.getJWTClaimsSet().getStringClaim("state"), equalTo(flow.getState()))
        if (!flow.getNonce().isEmpty()) {
            assertThat(signedJWT.getJWTClaimsSet().getStringClaim("nonce"), equalTo(flow.getNonce()))
        }
        return signedJWT
    }

    private static void addJsonAttachment(String name, String json) throws IOException {
        ObjectMapper mapper = new ObjectMapper()
        Object jsonObject = mapper.readValue(json, Object.class)
        String prettyJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObject)
        Allure.addAttachment(name, "application/json", prettyJson, "json")
    }
}
