package ee.ria.tara

import io.qameta.allure.Step
import io.qameta.allure.restassured.AllureRestAssured
import io.restassured.RestAssured
import io.restassured.response.Response

import static io.restassured.RestAssured.given
import static io.restassured.config.EncoderConfig.encoderConfig

class Requests {

    @Step("Init auth request")
    static Response initAuthRequest(Flow flow, String scopeList = "openid") {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .queryParam("scope", scopeList)
                        .queryParam("ui_locales", "et")
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .get(flow.oidcClient.fullRequestUrl)
                        .then()
                        .log().cookies()
                        .extract().response()
        return response
    }

    @Step("Mobile-ID authentication init request")
    static Response initMid(Flow flow) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .formParam("idCode", "60001017716")
                        .formParam("telephoneNumber", "69100366")
                        .cookie("SESSION", flow.sessionId)
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .post(flow.loginService.fullMidInitUrl)
                        .then()
                        .log().cookies()
                        .extract().response()
        return response
    }

    @Step("Mobile-ID response poll request")
    static Response pollMid(Flow flow) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .cookie("SESSION", flow.sessionId)
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .get(flow.loginService.fullMidPollUrl)
                        .then()
                        .log().cookies()
                        .extract().response()
        return response
    }

    @Step("Follow redirect request")
    static Response followRedirect(Flow flow, String location) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(true)
                .get(location)
                .then()
                .log().cookies()
                .extract().response()
    }

    @Step("Follow redirect request with session id")
    static Response followRedirectWithSessionId(Flow flow,String requestType, String location) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .cookie("SESSION", flow.sessionId)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                .baseUri(flow.loginService.baseUrl)
                .when()
                .redirects().follow(false)
                .request(requestType, location)
                .then()
                .log().cookies()
                .extract().response()
    }

    @Step("Follow redirect request with session id and cookies")
    static Response followRedirectWithSessionIdAndCookies(Flow flow,String requestType, String location, Map cookies) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .cookie("SESSION", flow.sessionId)
                .cookies(cookies)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                .baseUri(flow.loginService.baseUrl)
                .when()
                .redirects().follow(false)
                .request(requestType, location)
                .then()
                .log().cookies()
                .extract().response()
    }

    @Step("Follow redirect with cookie request")
    static Response followRedirectWithCookie(Flow flow, String location, Map myCookies) {
        return given()
                .filter(flow.cookieFilter)
                .cookies(myCookies)
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .log().cookies()
                .extract().response()
    }

    @Step("Get request with cookies and params")
    static Response getRequestWithCookiesAndParams(Flow flow , String url
                                                   , Map<String, String> cookies
                                                   , Map<String, String> queryParams
                                                   , Map<String, String> additionalQueryParams) {
        return given()
                .filter(flow.cookieFilter)
                .cookies(cookies)
                .queryParams(queryParams)
                .queryParams(additionalQueryParams)
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(url)
                .then()
                .log().cookies()
                .extract().response()
    }

    @Step("Get request with sessionID, cookies and params")
    static Response getRequestWithSessionIDCookiesAndParams(Flow flow , String url
                                                   , Map<String, String> cookies
                                                   , Map<String, String> queryParams
                                                   , Map<String, String> additionalQueryParams) {
        return given()
                .filter(flow.cookieFilter)
                .cookie("SESSION", flow.sessionId)
                .cookies(cookies)
                .queryParams(queryParams)
                .queryParams(additionalQueryParams)
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(url)
                .then()
                .log().cookies()
                .extract().response()
    }

    @Step("Get request with params")
    static Response getRequestWithParams(Flow flow , String url
                                                   , Map<String, String> queryParams
                                                   , Map<String, String> additionalQueryParams) {
        return given()
                .filter(flow.cookieFilter)
                .queryParams(queryParams)
                .queryParams(additionalQueryParams)
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(url)
                .then()
                .log().cookies()
                .extract().response()
    }

    @Step("Post request with cookies and params")
    static Response postRequestWithCookiesAndParams(Flow flow , String url
                                                   , Map<String, String> cookies
                                                   , Map<String, String> formParams
                                                   , Map<String, String> additionalFormParams) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .cookies(cookies)
                .formParams(formParams)
                .formParams(additionalFormParams)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                .when()
                .post(url)
                .then()
                .extract().response()
    }

    // TODO remove method?
    @Step("Post request with params")
    static Response postRequestWithParams(Flow flow , String url
                                                    , Map<String, String> formParams
                                                    , Map<String, String> additionalFormParams) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .formParams(formParams)
                .formParams(additionalFormParams)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                .baseUri(flow.loginService.baseUrl)
                .when()
                .post(url)
                .then()
                .extract().response()
    }

    @Step("Post request with headers, cookies and params")
    static Response postRequestWithHeadersCookiesAndParams(Flow flow , String url
                                                    , Map<String, String> headers
                                                    , Map<String, String> cookies
                                                    , Map<String, String> formParams) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .cookies(cookies)
                .headers(headers)
                .formParams(formParams)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                .when()
                .post(url)
                .then()
                .extract().response()
    }

    @Step("Get heartbeat")
    static Response getHeartbeat(Flow flow) {
        return given()
                .filter(new AllureRestAssured())
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                .when()
                .get(flow.loginService.fullHeartbeatUrl)
                .then()
                .statusCode(200)
                .extract().response()
    }

    @Step("Get request with ID-Card authentication")
    static Response idCardAuthentication(Flow flow , Map<String, String> headers) {
        return given()
                .filter(flow.cookieFilter)
                .headers(headers)
                .cookie("SESSION", flow.sessionId)
                .relaxedHTTPSValidation()
                .filter(new AllureRestAssured())
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(flow.loginService.fullIdCardInitUrl)
                .then()
                .log().cookies()
                .extract().response()
    }

}
