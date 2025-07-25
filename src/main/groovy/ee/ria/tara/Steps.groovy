package ee.ria.tara

import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.JOSEException
import com.nimbusds.jwt.SignedJWT
import ee.ria.tara.model.LoA
import io.qameta.allure.Allure
import io.qameta.allure.Step
import io.qameta.allure.model.Link
import io.restassured.http.Method
import io.restassured.response.Response
import org.apache.http.HttpStatus
import org.json.JSONObject

import java.text.ParseException

import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.anyOf
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.MatcherAssert.assertThat


class Steps {

    @Step("Initialize authentication sequence in OIDC service with params")
    static Response startAuthenticationInOidcWithParams(Flow flow, Map paramsMap) {
        Response initSession = Requests.getRequestWithParams(flow, flow.oidcService.fullAuthorizationUrl, paramsMap)
        flow.oidcService.cookies << initSession.getCookies()
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
        flow.setSessionId(initLogin.getCookie("__Host-SESSION"))
        flow.setLocale(initLogin.getCookie("__Host-LOCALE"))
        // TODO initLogin.body("input", contains("_csrf"))
        if (initLogin.body.asString().contains("_csrf")) { // TARA2-121
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
    static Response startAuthenticationInTaraWithAcr(Flow flow, LoA acr_values, boolean checkStatusCode = true) {
        Map paramsMap = OpenIdUtils.getAuthorizationParametersWithAcrValues(flow, acr_values)
        Response initOIDCServiceSession = startAuthenticationInOidcWithParams(flow, paramsMap)
        Response initLoginSession = createLoginSession(flow, initOIDCServiceSession)
        if (checkStatusCode) {
            assertThat("Correct HTTP status code", initLoginSession.statusCode, is(200))
        }
        return initLoginSession
    }

    @Step("Start authentication in TARA with specified client and follow redirects")
    static Response startAuthenticationInTaraWithClient(Flow flow, String clientId, String clientSecret, String redirectUri, boolean checkStatusCode = true) {
        Map paramsMap = OpenIdUtils.getAuthorizationParametersWithClient(flow, clientId, clientSecret, redirectUri)
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
    static Response initMidAuthSession(Flow flow, String idCode, String telephoneNumber) {
        Map formParamsMap = [_csrf          : flow.csrf,
                             idCode         : idCode,
                             telephoneNumber: telephoneNumber]
        return Requests.postRequestWithParams(flow, flow.loginService.fullMidInitUrl, formParamsMap)
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
        Requests.startMidAuthentication(flow, idCode, phoneNo).then().statusCode(HttpStatus.SC_OK)
        pollMidResponse(flow).then()
                .statusCode(HttpStatus.SC_OK)
                .body("status", is("COMPLETED"))
        Response acceptResponse = Requests.postRequest(flow, flow.loginService.fullAuthAcceptUrl)
        acceptResponse.then().statusCode(HttpStatus.SC_MOVED_TEMPORARILY)
        Response oidcServiceResponse = loginVerifier(flow, acceptResponse)
        Response consentResponse = followRedirectWithSessionId(flow, oidcServiceResponse)
        return consentResponse
    }

    @Step("Authenticate with Smart-ID")
    static Response authenticateWithSid(Flow flow, String idCode) {
        Response sidInit = initSidAuthSession(flow, idCode)
        assertThat("Correct HTTP status code", sidInit.statusCode, is(200))
        Response sidPollResult = pollSidResponse(flow)
        assertThat("Correct HTTP status code", sidPollResult.statusCode, is(200))
        assertThat(sidPollResult.jsonPath().getString("status"), is("COMPLETED"))
        Response acceptResponse = Requests.postRequest(flow, flow.loginService.fullAuthAcceptUrl)
        assertThat("Correct HTTP status code", acceptResponse.statusCode, is(302))
        Response oidcServiceResponse = loginVerifier(flow, acceptResponse)
        assertThat("Correct HTTP status code", oidcServiceResponse.statusCode, is(302))
        Response consentResponse = followRedirectWithSessionId(flow, oidcServiceResponse)
        return consentResponse
    }

    @Step("Authenticate with Web eID")
    static Response authenticateWithWebEid(Flow flow, boolean clientSecretBasic = true) {

        Response initWebEid = Requests.postRequest(flow, flow.loginService.fullWebEidInitUrl)
        String signAuthValue = Utils.signAuthenticationValue(flow, flow.loginService.baseUrl, initWebEid.jsonPath().get("nonce"))
        JSONObject authToken = Utils.getWebEidAuthTokenParameters(flow, signAuthValue)
        Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        Response acceptResponse = Requests.postRequest(flow, flow.loginService.fullAuthAcceptUrl)
        Response loginVerifier = loginVerifier(flow, acceptResponse)
        Response consentResponse = followRedirectWithSessionId(flow, loginVerifier)
        Response consentVerifier = followRedirectWithCookies(flow, consentResponse, flow.oidcService.cookies)
        String authorizationCode = Utils.getParamValueFromResponseHeader(consentVerifier, "code")
        flow.setCode(authorizationCode)
        if (clientSecretBasic) {
            return Requests.webTokenBasicRequest(flow, authorizationCode, flow.clientId, flow.clientSecret, flow.redirectUri)
        } else {
            return Requests.webTokenPostRequest(flow, authorizationCode)
        }
    }

    @Step("Initialize Smart-ID authentication session")
    static Response initSidAuthSession(Flow flow, Object idCode) {
        Map formParamsMap = ["_csrf": flow.csrf,
                             idCode : idCode]
        return Requests.postRequestWithParams(flow, flow.loginService.fullSidInitUrl, formParamsMap)
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

    @Step("OIDC login verifier request")
    static Response loginVerifier(Flow flow, Response response) {
        Response oidcServiceResponse = followRedirectWithCookies(flow, response, flow.oidcService.cookies)
        flow.oidcService.cookies << oidcServiceResponse.getCookies()
        oidcServiceResponse.then().statusCode(HttpStatus.SC_MOVED_TEMPORARILY)
        return oidcServiceResponse
    }

    @Step("Initialize authentication session")
    static Response initLoginSession(Flow flow, Response response, Map paramsMap) {
        Response initResponse = Requests.getRequestWithParams(flow, response.getHeader("location"), paramsMap)
        flow.setSessionId(initResponse.getCookie("__Host-SESSION"))
        flow.setCsrf(initResponse.htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        return initResponse
    }

    @Step("Follow redirect")
    static Response followRedirect(Flow flow, Response response) {
        return Requests.followRedirect(flow, response.getHeader("location"))
    }

    @Step("Follow redirect with cookies")
    static Response followRedirectWithCookies(Flow flow, Response response, Map cookies) {
        return Requests.followRedirectWithCookie(flow, response.getHeader("location"), cookies)
    }

    @Step("Follow redirect with session id")
    static Response followRedirectWithSessionId(Flow flow, Response response) {
        return Requests.getRequest(flow, response.getHeader("location"))
    }

    @Step("Confirm or reject consent")
    static Response submitConsent(Flow flow, boolean consentGiven) {
        Map formParamsMap = [consent_given: consentGiven,
                             _csrf        : flow.csrf]
        Response consentConfirmResponse = Requests.postRequestWithParams(flow, flow.loginService.fullConsentConfirmUrl, formParamsMap)
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
        return Requests.webTokenBasicRequest(flow, authorizationCode)
    }

    @Step("Get identity token response with OIDC client details")
    static Response getIdentityTokenResponseWithClient(Flow flow, Response response, String clientId, String clientSecret, String redirectUrl) {
        String authorizationCode = Utils.getParamValueFromResponseHeader(response, "code")
        return Requests.webTokenBasicRequest(flow, authorizationCode, clientId, clientSecret, redirectUrl)
    }

    @Step("verify token")
    static SignedJWT verifyTokenAndReturnSignedJwtObject(Flow flow, String token) throws ParseException, JOSEException, IOException {
        SignedJWT signedJWT = SignedJWT.parse(token)
        //TODO: single attachment
        addJsonAttachment("Header", signedJWT.header.toString())
        addJsonAttachment("Payload", signedJWT.JWTClaimsSet.toString())
        try {
            Allure.link("View Token in jwt.io", new Link().toString(),
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
    static Response getUserInfoResponseWithHeaderParam(Flow flow, Method requestType, String accessToken) {
        Map headersMap = ["Authorization": "Bearer " + accessToken]
        return Requests.getUserInfoWithHeaderParam(flow, requestType, headersMap)
    }

    @Step("Get user info response with query parameter")
    static Response getUserInfoResponseWithQueryParam(Flow flow, Method requestType, String accessToken) {
        Map paramsMap = ["access_token": accessToken]
        return Requests.getUserInfoWithQueryParam(flow, requestType, paramsMap)
    }

    @Step("Autheticate with mID and init legal person authorization")
    static Response authInitAsLegalPerson(Flow flow) {
        Response initMidAuthenticationSession = initMidAuthSession(flow, "60001019906", "00000766")
        assertThat("Correct HTTP status code", initMidAuthenticationSession.statusCode, is(200))
        Response pollResponse = pollMidResponse(flow)
        assertThat("Correct HTTP status code", pollResponse.statusCode, is(200))
        assertThat(pollResponse.jsonPath().getString("status"), is("COMPLETED"))
        Response acceptResponse = Requests.postRequest(flow, flow.loginService.fullAuthAcceptUrl)
        assertThat("Correct HTTP status code", acceptResponse.statusCode, is(302))

        Response initLegalResponse = followRedirectWithSessionId(flow, acceptResponse)
        assertThat("Correct HTTP status code", initLegalResponse.statusCode, is(200))
        return initLegalResponse
    }

    @Step("Load legal persons list")
    static Response loadLegalPersonsList(Flow flow) {
        return Requests.getRequest(flow, flow.loginService.fullAuthLegalPersonUrl)
    }

    @Step("Select legal person and confirm it")
    static Response selectLegalPersonAndConfirmIt(Flow flow, String legalPersonIdentifier) {
        Response response = selectLegalPerson(flow, legalPersonIdentifier)
        String location = response.header("location")
        assertThat("Correct location header", location, containsString(flow.oidcService.fullAuthorizationUrl))
        Response oidcServiceResponse = loginVerifier(flow, response)
        assertThat("Correct HTTP status code", oidcServiceResponse.statusCode, is(302))
        Response consentResponse = followRedirectWithSessionId(flow, oidcServiceResponse)
        assertThat("Correct HTTP status code", consentResponse.statusCode, is(302))
        return consentResponse
    }

    @Step("Select legal person from list")
    static Response selectLegalPerson(Flow flow, String legalPersonIdentifier) {
        Map paramsMap = ["legal_person_identifier": legalPersonIdentifier,
                         "_csrf"                  : flow.csrf]
        Response response = Requests.postRequestWithParams(flow, flow.loginService.fullAuthLegalConfirmUrl, paramsMap)
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
