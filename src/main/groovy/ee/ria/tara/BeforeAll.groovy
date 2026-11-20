package ee.ria.tara

import ee.ria.tara.configuration.ConfigHolder
import ee.ria.tara.configuration.TestConf
import io.qameta.allure.restassured.AllureRestAssured
import io.restassured.RestAssured
import io.restassured.config.HttpClientConfig
import io.restassured.filter.log.RequestLoggingFilter
import io.restassured.filter.log.ResponseLoggingFilter

class BeforeAll {

    private static final int CONNECTION_TIMEOUT_MS = 10_000
    private static final int SOCKET_TIMEOUT_MS = 60_000

    TestConf conf = ConfigHolder.getTestConf()

    BeforeAll() {

        // Rest Assured settings
        // Log all requests and responses in allure report
        RestAssured.filters(new AllureRestAssured())
        // Relax validation
        RestAssured.useRelaxedHTTPSValidation()
        // Fail fast on unreachable hosts (e.g. blocked by ALB inbound-cidrs) instead of hanging for minutes on OS TCP timeouts.
        // Socket timeout stays above the longest legitimate response (Smart-ID TIMEOUT scenarios take ~31 s).
        RestAssured.config = RestAssured.config().httpClient(HttpClientConfig.httpClientConfig()
                .setParam("http.connection.timeout", CONNECTION_TIMEOUT_MS)
                .setParam("http.socket.timeout", SOCKET_TIMEOUT_MS))
        // Log requests and responses to console for debugging
        // Enabled when toggled in conf. If not configured, enabled when not running in docker (i.e. running locally).
        if (conf.restAssuredConsoleLogging() != null ? conf.restAssuredConsoleLogging() : Utils.isLocal()) {
            RestAssured.filters(new RequestLoggingFilter(), new ResponseLoggingFilter())
        }
    }
}
