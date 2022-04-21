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
import static org.hamcrest.Matchers.anyOf
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.equalTo

import static org.junit.jupiter.api.Assertions.assertEquals
import static org.hamcrest.MatcherAssert.assertThat


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
        assertEquals(302, initOIDCServiceSession.statusCode(), "Correct HTTP status code is returned")
        return initOIDCServiceSession
    }

    @Step("Initialize authentication sequence in login service")
    static Response createLoginSession(Flow flow, Response response) {
        Response initLogin = followRedirect(flow, response)
        flow.setSessionId(initLogin.getCookie("SESSION"))
        flow.setLogin_locale(initLogin.getCookie("LOGIN_LOCALE"))
        // TODO initLogin.body("input", contains("_csrf"))
        if (initLogin.body().prettyPrint().contains("_csrf")) { // TARA2-121
            flow.setCsrf(initLogin.body().htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        }
        return initLogin
    }

    @Step("Start authentication in TARA and follow redirects")
    static Response startAuthenticationInTara(Flow flow, String scopeList = "openid", String login_locale = "et", boolean checkStatusCode = true) {
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, scopeList, login_locale)
        Response initOIDCServiceSession = startAuthenticationInOidcWithParams(flow, paramsMap)
        Response initLoginSession = createLoginSession(flow, initOIDCServiceSession)
        if (checkStatusCode) {
            assertEquals(200, initLoginSession.statusCode(), "Correct HTTP status code is returned")
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
    static Response pollMidResponse(Flow flow, long pollingIntevalMillis = 2000L) {
        int counter = 0
        Response response = null
        while (counter < 12) {
            sleep(pollingIntevalMillis)
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
        assertEquals(200, midInit.statusCode(), "Correct HTTP status code is returned")
        Response midPollResult = Steps.pollMidResponse(flow)
        assertEquals(200, midPollResult.statusCode(), "Correct HTTP status code is returned")
        assertThat(midPollResult.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals(302, acceptResponse.statusCode(), "Correct HTTP status code is returned")

        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        assertEquals(302, oidcServiceResponse.statusCode(), "Correct HTTP status code is returned")

        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)

        return consentResponse
    }

    @Step("Authenticate with Smart-ID")
    static Response authenticateWithSid(Flow flow, String idCode) {
        Response sidInit = initSidAuthSession(flow, flow.sessionId, idCode, Collections.emptyMap())
        assertEquals(200, sidInit.statusCode(), "Correct HTTP status code is returned")
        Response sidPollResult = pollSidResponse(flow)
        assertEquals(200, sidPollResult.statusCode(), "Correct HTTP status code is returned")
        assertThat(sidPollResult.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals(302, acceptResponse.statusCode(), "Correct HTTP status code is returned")

        Response oidcServiceResponse = getOAuthCookies(flow, acceptResponse)
        assertEquals(302, oidcServiceResponse.statusCode(), "Correct HTTP status code is returned")

        Response consentResponse = followRedirectWithSessionId(flow, oidcServiceResponse)

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
        assertEquals(302, acceptResponse.statusCode(), "Correct HTTP status code is returned")
        Response oidcServiceResponse = getOAuthCookies(flow, acceptResponse)
        assertEquals(302, oidcServiceResponse.statusCode(), "Correct HTTP status code is returned")

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
        Utils.setParameter(cookieMap, "LOGIN_LOCALE", flow.login_locale)
        return Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullSidInitUrl, cookieMap, formParamsMap, additionalParamsMap)
    }

    @Step("Polling Smart-ID authentication response")
    static Response pollSidResponse(Flow flow , long pollingIntevalMillis = 2000L) {
        int counter = 0
        Response response = null
        while (counter < 20) {
            response = Requests.pollSid(flow)
            if (response.body().jsonPath().get("status") != "PENDING") {
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
        if (consentResponse.getStatusCode().toInteger() == 200) {
            consentResponse = submitConsent(flow, consentGiven)
            assertEquals(302, consentResponse.statusCode(), "Correct HTTP status code is returned")

        }
        return followRedirectWithCookies(flow, consentResponse, flow.oidcService.cookies)
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
        assertThat("Expected current: " + date + " to be after nbf: " + signedJWT.getJWTClaimsSet().getNotBeforeTime(), date.after(signedJWT.getJWTClaimsSet().getNotBeforeTime()), is(true))
        if (!flow.getNonce().isEmpty()) {
            assertThat(signedJWT.getJWTClaimsSet().getStringClaim("nonce"), equalTo(flow.getNonce()))
        }
        assertThat(signedJWT.getJWTClaimsSet().getStringClaim("state"), equalTo(flow.getState()))
        return signedJWT
    }

    @Step("verify response headers")
    static void verifyResponseHeaders(Response response) {
        assertThat(response.getHeader("X-Frame-Options"), equalTo("DENY"))
        String policyString = "connect-src 'self'; default-src 'none'; font-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; block-all-mixed-content"
        assertThat(response.getHeader("Content-Security-Policy"), equalTo(policyString))
        assertThat(response.getHeader("Strict-Transport-Security"), anyOf(containsString("max-age=16070400"), containsString("max-age=31536000")))
        assertThat(response.getHeader("Strict-Transport-Security"), containsString("includeSubDomains"))
        assertThat(response.getHeader("Cache-Control"), equalTo("no-cache, no-store, max-age=0, must-revalidate"))
        assertThat(response.getHeader("X-Content-Type-Options"), equalTo("nosniff"))
        assertThat(response.getHeader("X-XSS-Protection"), equalTo("0"))
        assertThat(response.getHeader("Expires"), equalTo("0"))
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

    @Step("Autheticate with mID and init legal person authorization")
    static Response authInitAsLegalPerson(Flow flow, String idCode, String phoneNo) {
        Response initMidAuthenticationSession = initMidAuthSession(flow, flow.sessionId, idCode, phoneNo, Collections.emptyMap())
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response pollResponse = pollMidResponse(flow)
        assertEquals(200, pollResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals(302, acceptResponse.statusCode(), "Correct HTTP status code is returned")

        Response initLegalResponse = followRedirectWithSessionId(flow, acceptResponse)
        assertEquals(200, initLegalResponse.statusCode(), "Correct HTTP status code is returned")
        return initLegalResponse
    }

    @Step("Load legal persons list")
    static Response loadLegalPersonsList(Flow flow) {
        Requests.getRequestWithSessionId(flow, flow.loginService.fullAuthLegalPersonUrl)
    }

    @Step("Select legal person and confirm it")
    static Response selectLegalPersonAndConfirmIt(Flow flow, String legalPersonIdentifier) {
        Response response = selectLegalPerson(flow, legalPersonIdentifier)
        String location = response.getHeader("location")
        assertThat(location, containsString(flow.oidcService.fullAuthenticationRequestUrl))
        Response oidcServiceResponse = getOAuthCookies(flow, response)
        assertEquals(302, oidcServiceResponse.statusCode(), "Correct HTTP status code is returned")

        Response consentResponse = followRedirectWithSessionId(flow, oidcServiceResponse)
        assertEquals(200, consentResponse.statusCode(), "Correct HTTP status code is returned")
        return consentResponse
    }

    @Step("Select legal person from list")
    static Response selectLegalPerson(Flow flow, String legalPersonIdentifier) {
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "legal_person_identifier", legalPersonIdentifier)
        def map3 = Utils.setParameter(paramsMap, "_csrf", flow.csrf)
        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(cookiesMap, "SESSION", flow.sessionId)

        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullAuthLegalConfirmUrl, cookiesMap, paramsMap, Collections.emptyMap())
        assertEquals(302, response.statusCode(), "Correct HTTP status code is returned")
        return response
    }

    private static void addJsonAttachment(String name, String json) throws IOException {
        ObjectMapper mapper = new ObjectMapper()
        Object jsonObject = mapper.readValue(json, Object.class)
        String prettyJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObject)
        Allure.addAttachment(name, "application/json", prettyJson, "json")
    }
}
