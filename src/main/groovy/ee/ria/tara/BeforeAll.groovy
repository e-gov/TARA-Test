package ee.ria.tara

import ee.ria.tara.configuration.ConfigHolder
import ee.ria.tara.configuration.TestConf
import io.qameta.allure.restassured.AllureRestAssured
import io.restassured.RestAssured
import io.restassured.filter.log.RequestLoggingFilter
import io.restassured.filter.log.ResponseLoggingFilter

class BeforeAll {

    TestConf conf = ConfigHolder.getTestConf()

    BeforeAll() {

        // Rest Assured settings
        // Log all requests and responses in allure report
        RestAssured.filters(new AllureRestAssured())
        // Relax validation
        RestAssured.useRelaxedHTTPSValidation()
        // Log requests and responses to console for debugging
        // Enabled when toggled in conf. If not configured, enabled when not running in docker (i.e. running locally).
        if (conf.restAssuredConsoleLogging() != null ? conf.restAssuredConsoleLogging() : Utils.isLocal()) {
            RestAssured.filters(new RequestLoggingFilter(), new ResponseLoggingFilter())
        }
    }
}
