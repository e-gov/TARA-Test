package ee.ria.tara

import io.qameta.allure.Step
import io.qameta.allure.restassured.AllureRestAssured
import io.restassured.http.ContentType
import io.restassured.path.json.JsonPath
import io.restassured.response.Response
import org.json.JSONObject

import static io.restassured.RestAssured.given

class Requests {

    @Step("Mobile-ID authentication init request")
    static Response startMidAuthentication(Flow flow, String idCode, String phoneNo) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .params([idCode         : idCode,
                         telephoneNumber: phoneNo,
                         _csrf          : flow.csrf])
                .cookie("__Host-SESSION", flow.sessionId)
                .log().cookies()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .redirects().follow(false)
                .post(flow.loginService.fullMidInitUrl)
    }

    @Step("Mobile-ID response poll request")
    static Response pollMid(Flow flow) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .cookie("__Host-SESSION", flow.sessionId)
                .log().cookies()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .redirects().follow(false)
                .get(flow.loginService.fullMidPollUrl)
    }

    @Step("Smart-ID response poll request")
    static Response pollSid(Flow flow) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .cookies(["__Host-SESSION": flow.sessionId,
                          "__Host-LOCALE" : flow.locale])
                .log().cookies()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .redirects().follow(false)
                .get(flow.loginService.fullSidPollUrl)
    }

    @Step("Follow redirect request")
    static Response followRedirect(Flow flow, String location) {
        return given()
                .filter(new AllureRestAssured())
                .filter(flow.cookieFilter)
                .log().cookies()
                .relaxedHTTPSValidation()
                .urlEncodingEnabled(true)
                .redirects().follow(false)
                .get(location)
    }

    @Step("Simple get request")
    static Response getRequest(Flow flow, String location) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .log().cookies()
                .relaxedHTTPSValidation()
                .urlEncodingEnabled(true)
                .baseUri(flow.loginService.baseUrl)
                .redirects().follow(false)
                .get(location)
    }

    @Step("Simple post request with form parameters")
    static Response postRequestWithParams(Flow flow, String location, Map parameters) {
        return given()
                .filter(flow.cookieFilter)
                .formParams(parameters)
                .contentType(ContentType.URLENC)
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .log().cookies()
                .post(location)
    }

    @Step("Login service post request with session id")
    static Response postRequest(Flow flow, String location) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .cookie("__Host-SESSION", flow.sessionId)
                .formParam("_csrf", flow.csrf)
                .log().cookies()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .redirects().follow(false)
                .post(location)
    }

    @Step("{1} request with session id")
    static Response requestWithType(Flow flow, String requestType, String location) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .formParam("_csrf", flow.csrf)
                .log().cookies()
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .redirects().follow(false)
                .request(requestType, location)
    }

    // TODO: review after dependency update. Current version does not handle OIDC cookies correctly
    @Step("Follow redirect with cookies request")
    static Response followRedirectWithCookie(Flow flow, String location, Map myCookies) {
        return given()
                .filter(flow.cookieFilter)
                .cookies(myCookies)
                .filter(new AllureRestAssured())
                .log().cookies()
                .relaxedHTTPSValidation()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(location)
    }

    @Step("Get request with params")
    static Response getRequestWithParams(Flow flow, String url, Map queryParams) {
        return given()
                .filter(flow.cookieFilter)
                .queryParams(queryParams)
                .filter(new AllureRestAssured())
                .log().cookies()
                .relaxedHTTPSValidation()
                .redirects().follow(false)
                .urlEncodingEnabled(true)
                .get(url)
    }

    @Step("Get heartbeat")
    static Response getHeartbeat(Flow flow) {
        return given()
                .filter(new AllureRestAssured())
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .get(flow.loginService.fullHeartbeatUrl)
                .then()
                .statusCode(200)
                .extract().response()
    }

    @Step("Download openid service configuration")
    static JsonPath getOpenidConfiguration(String url) {
        return given()
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .get(url)
                .then()
                .statusCode(200)
                .extract().jsonPath()
    }

    @Step("Download openid service JWKS")
    static InputStream getOpenidJwks(String url) {
        return given()
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .get(url)
                .then()
                .statusCode(200)
                .extract().body().asInputStream()
    }

    @Step("Get JWT with basic method")
    static Response webTokenBasicRequest(Flow flow,
                                         String authorizationCode,
                                         String clientId = flow.oidcClientPublic.clientId,
                                         String clientSecret = flow.oidcClientPublic.clientSecret,
                                         String redirectUri = flow.oidcClientPublic.fullResponseUrl) {
        return given()
                .filter(new AllureRestAssured())
                .params([grant_type  : "authorization_code",
                         code        : authorizationCode,
                         redirect_uri: redirectUri])
                .auth().preemptive().basic(clientId, clientSecret)
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .post(flow.openIdServiceConfiguration.getString("token_endpoint"))
    }

    @Step("Get token client_secret_post")
    static Response webTokenPostRequest(Flow flow, String authorizationCode) {
        return given()
                .filter(new AllureRestAssured())
                .params([grant_type   : "authorization_code",
                         redirect_uri : flow.redirectUri,
                         code         : authorizationCode,
                         client_id    : flow.clientId,
                         client_secret: flow.clientSecret])
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .post(flow.openIdServiceConfiguration.getString("token_endpoint"))
    }

    @Step("Get token response body")
    static Response getWebTokenResponseBody(Flow flow, Map formParams) {
        return given()
                .filter(new AllureRestAssured())
                .params(formParams)
                .auth().preemptive().basic(flow.oidcClientPublic.clientId, flow.oidcClientPublic.clientSecret)
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .post(flow.openIdServiceConfiguration.getString("token_endpoint"))
    }

    @Step("Get user info with header parameter")
    static Response getUserInfoWithHeaderParam(Flow flow, String requestType, Map headers) {
        return given()
                .filter(new AllureRestAssured())
                .headers(headers)
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .request(requestType, flow.openIdServiceConfiguration.getString("userinfo_endpoint"))
    }

    @Step("Get user info with query parameter")
    static Response getUserInfoWithQueryParam(Flow flow, String requestType, Map queryParams) {
        return given()
                .filter(new AllureRestAssured())
                .params(queryParams)
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .request(requestType, flow.openIdServiceConfiguration.getString("userinfo_endpoint"))
    }

    @Step("Post request with json body for admin api")
    static Response jsonRequest(Flow flow, String location, Map<String, Object> jsonAsMap) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .contentType(ContentType.JSON)
                .body(jsonAsMap)
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .post(location)
                .then()
                .log().cookies()
                .extract().response()
    }

    @Step("Post request with json body")
    static Response postRequestWithJsonBody(Flow flow, String location, JSONObject body) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .cookie("__Host-SESSION", flow.sessionId)
                .contentType("application/json")
                .header("X-CSRF-TOKEN", flow.csrf)
                .body(body.toString())
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .post(location)
                .then()
                .log().cookies()
                .extract().response()
    }

    @Step("Post request with json for admin api")
    static Response postRequestAdminApiWithJsonBody(Flow flow, String location, Map cookies, String body) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .header("X-XSRF-TOKEN", cookies.get("XSRF-TOKEN"))
                .cookies(cookies)
                .contentType(ContentType.JSON)
                .body(body)
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .post(location)
                .then()
                .log().cookies()
                .extract().response()
    }

    @Step("Delete request for admin api")
    static Response deleteRequest(Flow flow, String location, Map cookies) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .header("X-XSRF-TOKEN", cookies.get("XSRF-TOKEN"))
                .cookies(cookies)
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .delete(location)
    }

    @Step("Get request for admin api")
    static Response getRequest(Flow flow, String location, Map cookies) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .header("X-XSRF-TOKEN", cookies.get("XSRF-TOKEN"))
                .cookies(cookies)
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .get(location)
    }
}
