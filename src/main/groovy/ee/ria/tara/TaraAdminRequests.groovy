package ee.ria.tara

import io.qameta.allure.Step
import io.restassured.http.ContentType
import io.restassured.response.Response

import static io.restassured.RestAssured.given

class TaraAdminRequests {

    @Step("Post request with body")
    static Response postRequest(Flow flow, String location, Object body) {
        return given()
                .filter(flow.cookieFilter)
                .cookie("__Host-XSRF-TOKEN", flow.taraAdminService.xsrfToken)
                .header("X-XSRF-TOKEN", flow.taraAdminService.xsrfToken)
                .contentType(ContentType.JSON)
                .body(body)
                .urlEncodingEnabled(true)
                .post(location)
    }

    @Step("Delete request")
    static Response deleteRequest(Flow flow, String location) {
        return given()
                .filter(flow.cookieFilter)
                .cookie("__Host-XSRF-TOKEN", flow.taraAdminService.xsrfToken)
                .header("X-XSRF-TOKEN", flow.taraAdminService.xsrfToken)
                .urlEncodingEnabled(true)
                .delete(location)
    }

    @Step("Get request")
    static Response getRequest(Flow flow, String location) {
        return given()
                .filter(flow.cookieFilter)
                .cookie("__Host-XSRF-TOKEN", flow.taraAdminService.xsrfToken)
                .header("X-XSRF-TOKEN", flow.taraAdminService.xsrfToken)
                .urlEncodingEnabled(true)
                .get(location)
    }
}
