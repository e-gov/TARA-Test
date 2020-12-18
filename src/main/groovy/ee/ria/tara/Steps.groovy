package ee.ria.tara

import io.qameta.allure.Step
import io.restassured.response.Response
import org.spockframework.lang.Wildcard

import static org.junit.Assert.assertEquals

class Steps {
    static String REQUEST_TYPE_POST = "post"
    static String REQUEST_TYPE_GET = "get"

    @Step("Create client authentication session")
    static Response createAuthenticationSession(Flow flow, String scopeList = "openid") {
        Response initAuthResponse = Requests.initAuthRequest(flow, scopeList)
        String taraClientCookie = initAuthResponse.getCookie("TARAClient")
        Utils.setParameter(flow.oidcClient.cookies,"TARAClient", taraClientCookie)
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

    @Step("Create login session")
    static Response createLoginSession(Flow flow, Response response) {
        Response initLogin = followRedirect(flow, response)
        flow.setSessionId(initLogin.getCookie("SESSION"))
        return initLogin
    }

    @Step("Initialize Mobile-ID authentication session")
    static Response initMidAuthSession(Flow flow, String sessionId
                                       , Object idCode, Object telephoneNumber
                                       , Map additionalParamsMap = Collections.emptyMap()) {
        LinkedHashMap<String, String> formParamsMap = (LinkedHashMap)Collections.emptyMap()
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
            sleep(2000L)
        }
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
        return Requests.followRedirectWithSessionId(flow, REQUEST_TYPE_GET, location)
    }

    @Step("Init person authentication session")
    static void initAuthenticationSession(Flow flow, String scopeList = "openid") {
        Response initOIDCServiceSession = createSession(flow, scopeList)
        Response initLoginSession = createLoginSession(flow, initOIDCServiceSession)
        assertEquals("Correct HTTP status code is returned", 200, initLoginSession.statusCode())
    }

    @Step("authenticate with mobile_ID")
    static Response authWithMobileID(Flow flow) {
        Response initClientAuthenticationSession = initAuthenticationSession(flow)
        Response initMidAuthenticationSession = initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, pollResponse.statusCode())
        Response acceptResponse = Requests.followRedirectWithSessionId(flow, REQUEST_TYPE_POST, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 302, acceptResponse.statusCode())
        Response oidcServiceResponse = getOAuthCookies(flow, acceptResponse)
        assertEquals("Correct HTTP status code is returned", 302, oidcServiceResponse.statusCode())
        return oidcServiceResponse
    }

    static Response createSession(Flow flow, String scopeList = "openid") {
        Response initClientAuthenticationSession = createAuthenticationSession(flow, scopeList)
        assertEquals("Correct HTTP status code is returned", 302, initClientAuthenticationSession.statusCode())
        Response initOIDCServiceSession = createOIDCSession(flow, initClientAuthenticationSession)
        assertEquals("Correct HTTP status code is returned", 302, initOIDCServiceSession.statusCode())
        return initOIDCServiceSession
    }
}
