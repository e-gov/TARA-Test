package ee.ria.tara

import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.JOSEException
import com.nimbusds.jwt.SignedJWT
import io.qameta.allure.Allure
import io.qameta.allure.Step
import io.restassured.response.Response
import org.json.JSONObject
import org.spockframework.lang.Wildcard

import java.text.ParseException

import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.anyOf
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.MatcherAssert.assertThat


class Steps {

    @Step("Initialize authentication sequence in OIDC service with params")
    static Response startAuthenticationInOidcWithParams(Flow flow, Map paramsMap) {
        Response initSession = Requests.getRequestWithParams(flow, flow.oidcService.fullAuthenticationRequestUrl, paramsMap, [:])
        Utils.setParameter(flow.oidcService.cookies, "oauth2_authentication_csrf", initSession.getCookie("oauth2_authentication_csrf"))
        flow.setLoginChallenge(Utils.getParamValueFromResponseHeader(initSession, "login_challenge"))
        return initSession
    }

    @Step("Initialize authentication sequence in OIDC service with defaults")
    static Response startAuthenticationInOidc(Flow flow) {
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        Response initOIDCServiceSession = startAuthenticationInOidcWithParams(flow, paramsMap)
        assertThat("Correct HTTP status code", initOIDCServiceSession.statusCode, is(302))
        return initOIDCServiceSession
    }

    @Step("Initialize authentication sequence in login service")
    static Response createLoginSession(Flow flow, Response response) {
        Response initLogin = followRedirect(flow, response)
        flow.setSessionId(initLogin.getCookie("SESSION"))
        flow.setLogin_locale(initLogin.getCookie("LOGIN_LOCALE"))
        // TODO initLogin.body("input", contains("_csrf"))
        if (initLogin.body.prettyPrint().contains("_csrf")) { // TARA2-121
            flow.setCsrf(initLogin.htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        }
        return initLogin
    }

    @Step("Start authentication in TARA and follow redirects")
    static Response startAuthenticationInTara(Flow flow, String scopeList = "openid", String login_locale = "et", boolean checkStatusCode = true) {
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, scopeList, login_locale)
        Response initOIDCServiceSession = startAuthenticationInOidcWithParams(flow, paramsMap)
        Response initLoginSession = createLoginSession(flow, initOIDCServiceSession)
        if (checkStatusCode) {
            assertThat("Correct HTTP status code", initLoginSession.statusCode, is(200))
        }
        return initLoginSession
    }

    @Step("Start authentication in TARA with acr_values and follow redirects")
    static Response startAuthenticationInTaraWithAcr(Flow flow, String acr_values, boolean checkStatusCode = true) {
        Map paramsMap = OpenIdUtils.getAuthorizationParametersWithAcrValues(flow, acr_values)
        Response initOIDCServiceSession = startAuthenticationInOidcWithParams(flow, paramsMap)
        Response initLoginSession = createLoginSession(flow, initOIDCServiceSession)
        if (checkStatusCode) {
            assertThat("Correct HTTP status code", initLoginSession.statusCode, is(200))
        }
        return initLoginSession
    }

    @Step("Start authentication in TARA with specified client and follow redirects")
    static Response startAuthenticationInTaraWithClient(Flow flow, String scopeList = "openid", String clientId, String redirectUri, boolean checkStatusCode = true) {
        Map paramsMap = OpenIdUtils.getAuthorizationParametersWithClient(flow, scopeList, clientId, redirectUri)
        Response initOIDCServiceSession = startAuthenticationInOidcWithParams(flow, paramsMap)
        Response initLoginSession = createLoginSession(flow, initOIDCServiceSession)
        if (checkStatusCode) {
            assertThat("Correct HTTP status code", initLoginSession.statusCode, is(200))
        }
        return initLoginSession
    }

    @Step("Start authentication in TARA with legalperson client and follow redirects")
    static Response startAuthenticationInTaraWithLegalPerson(Flow flow, String scopeList = "openid legalperson", boolean checkStatusCode = true) {
        Map paramsMap = OpenIdUtils.getAuthorizationParametersForLegalPersonClient(flow, scopeList)
        Response initOIDCServiceSession = startAuthenticationInOidcWithParams(flow, paramsMap)
        Response initLoginSession = createLoginSession(flow, initOIDCServiceSession)
        if (checkStatusCode) {
            assertThat("Correct HTTP status code", initLoginSession.statusCode, is(200))
        }
        return initLoginSession
    }

    @Step("Start authentication in TARA with Specific Proxy Service and follow redirects")
    static Response startAuthenticationInTaraWithSpecificProxyService(Flow flow, String scopeList = "openid", String login_locale = "et", boolean checkStatusCode = true) {
        Map paramsMap = OpenIdUtils.getAuthorizationParametersForSpecificProxyService(flow, scopeList, login_locale)
        Response initOIDCServiceSession = startAuthenticationInOidcWithParams(flow, paramsMap)
        Response initLoginSession = createLoginSession(flow, initOIDCServiceSession)
        if (checkStatusCode) {
            assertThat("Correct HTTP status code", initLoginSession.statusCode, is(200))
        }
        return initLoginSession
    }

    @Step("Initialize Mobile-ID authentication session")
    static Response initMidAuthSession(Flow flow, String sessionId
                                       , Object idCode, Object telephoneNumber
                                       , Map additionalParamsMap = [:]) {
        Map formParamsMap = ["_csrf": flow.csrf]
        if (!(idCode instanceof Wildcard)) {
            Utils.setParameter(formParamsMap, "idCode", idCode)
        }
        if (!(telephoneNumber instanceof Wildcard)) {
            Utils.setParameter(formParamsMap, "telephoneNumber", telephoneNumber)
        }
        Map cookieMap = ["SESSION": sessionId]

        return Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullMidInitUrl, cookieMap, formParamsMap, additionalParamsMap)
    }

    @Step("Polling Mobile-ID authentication response")
    static Response pollMidResponse(Flow flow, long pollingIntevalMillis = 2000L) {
        int counter = 0
        Response response = null
        while (counter < 12) {
            sleep(pollingIntevalMillis)
            response = Requests.pollMid(flow)
            if (response.jsonPath().get("status") != "PENDING") {
                break
            }
            ++counter
        }
        return response
    }

    @Step("Authenticate with Mobile-ID")
    static Response authenticateWithMid(Flow flow, String idCode, String phoneNo) {
        Response midInit = Requests.startMidAuthentication(flow, idCode, phoneNo)
        assertThat("Correct HTTP status code", midInit.statusCode, is(200))
        Response midPollResult = pollMidResponse(flow)
        assertThat("Correct HTTP status code", midPollResult.statusCode, is(200))
        assertThat(midPollResult.jsonPath().getString("status"), is("COMPLETED"))
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertThat("Correct HTTP status code", acceptResponse.statusCode, is(302))

        Response oidcServiceResponse = getOAuthCookies(flow, acceptResponse)
        assertThat("Correct HTTP status code", oidcServiceResponse.statusCode, is(302))

        Response consentResponse = followRedirectWithSessionId(flow, oidcServiceResponse)

        return consentResponse
    }

    @Step("Authenticate with Smart-ID")
    static Response authenticateWithSid(Flow flow, String idCode) {
        Response sidInit = initSidAuthSession(flow, flow.sessionId, idCode, [:])
        assertThat("Correct HTTP status code", sidInit.statusCode, is(200))
        Response sidPollResult = pollSidResponse(flow)
        assertThat("Correct HTTP status code", sidPollResult.statusCode, is(200))
        assertThat(sidPollResult.jsonPath().get("status").toString(), is("COMPLETED"))
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertThat("Correct HTTP status code", acceptResponse.statusCode, is(302))

        Response oidcServiceResponse = getOAuthCookies(flow, acceptResponse)
        assertThat("Correct HTTP status code", oidcServiceResponse.statusCode, is(302))

        Response consentResponse = followRedirectWithSessionId(flow, oidcServiceResponse)

        return consentResponse
    }

    @Step("Authenticate with Web eID")
    static Response authenticateWithWebeID(Flow flow) {

        Response initWebEid = Requests.postRequestWithSessionId(flow, flow.loginService.fullWebEidInitUrl)
        String signAuthValue = Utils.signAuthenticationValue(flow, flow.loginService.baseUrl, initWebEid.jsonPath().get("nonce"))
        JSONObject authToken = Utils.getWebEidAuthTokenParameters(flow, signAuthValue)
        Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        Response oidcServiceResponse = getOAuthCookies(flow, acceptResponse)
        Response consentResponse = followRedirectWithSessionId(flow, oidcServiceResponse)
        Response oidcserviceResponse = followRedirectWithCookies(flow, consentResponse, flow.oidcService.cookies)
        String authorizationCode = Utils.getParamValueFromResponseHeader(oidcserviceResponse, "code")
        Response tokenResponse = Requests.getWebToken(flow, authorizationCode)

        return tokenResponse
    }

    @Step("Initialize Smart-ID authentication session")
    static Response initSidAuthSession(Flow flow, String sessionId
                                       , Object idCode
                                       , Map additionalParamsMap = [:]) {
        Map formParamsMap = ["_csrf": flow.csrf]
        if (!(idCode instanceof Wildcard)) {
            Utils.setParameter(formParamsMap, "idCode", idCode)
        }
        Map cookieMap = [
                "SESSION"     : sessionId,
                "LOGIN_LOCALE": flow.login_locale]
        return Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullSidInitUrl, cookieMap, formParamsMap, additionalParamsMap)
    }

    @Step("Polling Smart-ID authentication response")
    static Response pollSidResponse(Flow flow, long pollingIntevalMillis = 2000L) {
        int counter = 0
        Response response = null
        while (counter < 20) {
            response = Requests.pollSid(flow)
            if (response.jsonPath().get("status") != "PENDING") {
                break
            }
            ++counter
            sleep(pollingIntevalMillis)
        }
        return response
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
    static Response initLoginSession(Flow flow, Response response, Map additionalParamsMap) {
        String location = response.then().extract().response().header("location")
        Response initResponse = Requests.getRequestWithCookiesAndParams(flow, location, [:], [:], additionalParamsMap)
        flow.setSessionId(initResponse.getCookie("SESSION"))
        flow.setCsrf(initResponse.htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        return initResponse
    }

    @Step("Follow redirect")
    static Response followRedirect(Flow flow, Response response) {
        String location = response.then().extract().response().header("location")
        return Requests.followRedirect(flow, location)
    }

    @Step("Follow redirect with cookies")
    static Response followRedirectWithCookies(Flow flow, Response response, Map cookies) {
        String location = response.then().extract().response().header("location")
        return Requests.followRedirectWithCookie(flow, location, cookies)
    }

    @Step("Follow redirect with session id")
    static Response followRedirectWithSessionId(Flow flow, Response response) {
        String location = response.then().extract().response().header("location")
        return Requests.getRequestWithSessionId(flow, location)
    }

    @Step("Confirm or reject consent")
    static Response submitConsent(Flow flow, boolean consentGiven) {
        Map cookiesMap = ["SESSION": flow.sessionId]
        Map formParamsMap = [
                "consent_given": consentGiven,
                "_csrf"        : flow.csrf]
        Response consentConfirmResponse = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullConsentConfirmUrl, cookiesMap, formParamsMap, [:])
        return consentConfirmResponse
    }

    @Step("Confirm or reject consent and finish authentication process")
    static Response submitConsentAndFollowRedirects(Flow flow, boolean consentGiven, Response consentResponse) {
        if (consentResponse.statusCode.toInteger() == 200) {
            consentResponse = submitConsent(flow, consentGiven)
            assertThat("Correct HTTP status code", consentResponse.statusCode, is(302))

        }
        return followRedirectWithCookies(flow, consentResponse, flow.oidcService.cookies)
    }

    @Step("Get identity token")
    static Response getIdentityTokenResponse(Flow flow, Response response) {
        String authorizationCode = Utils.getParamValueFromResponseHeader(response, "code")
        return Requests.getWebToken(flow, authorizationCode)
    }

    @Step("Get identity token response with OIDC client details")
    static Response getIdentityTokenResponseWithClient(Flow flow, Response response, String redirectUrl, String clientId, String clientSecret) {
        String authorizationCode = Utils.getParamValueFromResponseHeader(response, "code")
        return Requests.getWebTokenWithClient(flow, authorizationCode, redirectUrl, clientId, clientSecret)
    }

    @Step("verify token")
    static SignedJWT verifyTokenAndReturnSignedJwtObject(Flow flow, String token) throws ParseException, JOSEException, IOException {
        SignedJWT signedJWT = SignedJWT.parse(token)
        //TODO: single attachment
        addJsonAttachment("Header", signedJWT.header.toString())
        addJsonAttachment("Payload", signedJWT.JWTClaimsSet.toString())
        try {
            Allure.link("View Token in jwt.io", new io.qameta.allure.model.Link().toString(),
                    "https://jwt.io/#debugger-io?token=" + token)
        } catch (Exception e) {
            //NullPointerException when running test from IntelliJ
        }
        assertThat("Token Signature is not valid!", OpenIdUtils.isTokenSignatureValid(flow.jwkSet, signedJWT), is(true))
        assertThat(signedJWT.JWTClaimsSet.issuer, equalTo(flow.openIdServiceConfiguration.get("issuer")))
        Date date = new Date()
        assertThat("Expected current: " + date + " to be before exp: " + signedJWT.JWTClaimsSet.expirationTime, date.before(signedJWT.JWTClaimsSet.expirationTime), is(true))
        assertThat("Expected current: " + date + " to be after nbf: " + signedJWT.JWTClaimsSet.notBeforeTime, date.after(signedJWT.JWTClaimsSet.notBeforeTime), is(true))
        if (!flow.nonce.isEmpty()) {
            assertThat(signedJWT.JWTClaimsSet.getStringClaim("nonce"), is(flow.nonce))
        }
        assertThat(signedJWT.JWTClaimsSet.getStringClaim("state"), is(flow.state))
        return signedJWT
    }

    @Step("verify response headers")
    static void verifyResponseHeaders(Response response) {
        assertThat(response.header("X-Frame-Options"), is("DENY"))
        String policyString = "connect-src 'self'; " +
                "default-src 'none'; " +
                "font-src 'self'; " +
                "img-src 'self' data:; " +
                "script-src 'self'; " +
                "style-src 'self'; " +
                "base-uri 'none'; " +
                "frame-ancestors 'none'; " +
                "block-all-mixed-content"
        assertThat(response.header("Content-Security-Policy"), is(policyString))
        assertThat(response.header("Strict-Transport-Security"), anyOf(containsString("max-age=16070400"), containsString("max-age=31536000")))
        assertThat(response.header("Strict-Transport-Security"), containsString("includeSubDomains"))
        assertThat(response.header("Cache-Control"), is("no-cache, no-store, max-age=0, must-revalidate"))
        assertThat(response.header("X-Content-Type-Options"), is("nosniff"))
        assertThat(response.header("X-XSS-Protection"), is("0"))
        assertThat(response.header("Expires"), is("0"))
    }

    @Step("Get user info response with header parameter")
    static Response getUserInfoResponseWithHeaderParam(Flow flow, String requestType, String accessToken) {
        Map headersMap = ["Authorization": "Bearer " + accessToken]
        return Requests.getUserInfoWithHeaderParam(flow, requestType, headersMap)
    }

    @Step("Get user info response with query parameter")
    static Response getUserInfoResponseWithQueryParam(Flow flow, String requestType, String accessToken) {
        Map paramsMap = ["access_token": accessToken]
        return Requests.getUserInfoWithQueryParam(flow, requestType, paramsMap)
    }

    @Step("Autheticate with mID and init legal person authorization")
    static Response authInitAsLegalPerson(Flow flow, String idCode, String phoneNo) {
        Response initMidAuthenticationSession = initMidAuthSession(flow, flow.sessionId, idCode, phoneNo, [:])
        assertThat("Correct HTTP status code", initMidAuthenticationSession.statusCode, is(200))
        Response pollResponse = pollMidResponse(flow)
        assertThat("Correct HTTP status code", pollResponse.statusCode, is(200))
        assertThat(pollResponse.jsonPath().get("status").toString(), is("COMPLETED"))
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertThat("Correct HTTP status code", acceptResponse.statusCode, is(302))

        Response initLegalResponse = followRedirectWithSessionId(flow, acceptResponse)
        assertThat("Correct HTTP status code", initLegalResponse.statusCode, is(200))
        return initLegalResponse
    }

    @Step("Load legal persons list")
    static Response loadLegalPersonsList(Flow flow) {
        return Requests.getRequestWithSessionId(flow, flow.loginService.fullAuthLegalPersonUrl)
    }

    @Step("Select legal person and confirm it")
    static Response selectLegalPersonAndConfirmIt(Flow flow, String legalPersonIdentifier) {
        Response response = selectLegalPerson(flow, legalPersonIdentifier)
        String location = response.header("location")
        assertThat("Correct location header", location, containsString(flow.oidcService.fullAuthorizationUrl))
        Response oidcServiceResponse = getOAuthCookies(flow, response)
        assertThat("Correct HTTP status code", oidcServiceResponse.statusCode, is(302))

        Response consentResponse = followRedirectWithSessionId(flow, oidcServiceResponse)
        assertThat("Correct HTTP status code", consentResponse.statusCode, is(302))
        return consentResponse
    }

    @Step("Select legal person from list")
    static Response selectLegalPerson(Flow flow, String legalPersonIdentifier) {
        Map paramsMap = ["legal_person_identifier": legalPersonIdentifier,
                         "_csrf"                  : flow.csrf]
        Map cookiesMap = ["SESSION": flow.sessionId]

        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullAuthLegalConfirmUrl, cookiesMap, paramsMap, [:])
        assertThat("Correct HTTP status code", response.statusCode, is(302))
        return response
    }

    private static void addJsonAttachment(String name, String json) throws IOException {
        ObjectMapper mapper = new ObjectMapper()
        Object jsonObject = mapper.readValue(json, Object.class)
        String prettyJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObject)
        Allure.addAttachment(name, "application/json", prettyJson, "json")
    }
}
