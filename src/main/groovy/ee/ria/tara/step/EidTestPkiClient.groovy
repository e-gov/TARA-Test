package ee.ria.tara.step

import ee.ria.tara.configuration.ConfigHolder
import io.qameta.allure.Step
import io.restassured.http.ContentType
import org.apache.http.HttpStatus

import static io.restassured.RestAssured.given

class EidTestPkiClient {

    static String managerUrl = ConfigHolder.eidTestPkiService.managementApiUrl()

    @Step("Issue eID test leaf certificate [{caId}/{code}]")
    static issueAuthCert(String caId, String code, String surname, String givenName) {
        given()
                .baseUri(managerUrl)
                .contentType(ContentType.JSON)
                .body([code: code, surname: surname, given: givenName, type: "auth"])
                .post("/cas/${caId}/leaves")
                .then().statusCode(HttpStatus.SC_CREATED)
    }

    @Step("Fetch issued leaf keystore [{caId}/{code}/auth.p12]")
    static byte[] getAuthCertP12(String caId, String code, String password) {
        return given()
                .baseUri(managerUrl)
                .queryParam("password", password)
                .get("/cas/${caId}/leaves/${code}/auth.p12")
                .then().statusCode(HttpStatus.SC_OK)
                .extract().body().asByteArray()
    }

    @Step("Set leaf revocation status [{caId}/{code}/auth -> {status}]")
    static setAuthCertStatus(String caId, String code, String status, String reason = null) {
        Map body = [status: status]
        if (reason != null) {
            body.reason = reason
        }
        given()
                .baseUri(managerUrl)
                .contentType(ContentType.JSON)
                .body(body)
                .put("/cas/${caId}/leaves/${code}/auth/status")
                .then().statusCode(HttpStatus.SC_OK)
    }

    @Step("Set CA OCSP responder availability [{caId} -> enabled={enabled}]")
    static setOcspEnabled(String caId, boolean enabled) {
        given()
                .baseUri(managerUrl)
                .contentType(ContentType.JSON)
                .body([enabled: enabled])
                .put("/cas/${caId}/ocsp")
                .then().statusCode(HttpStatus.SC_OK)
    }

    @Step("Set CA CRL availability [{caId} -> enabled={enabled}]")
    static setCrlEnabled(String caId, boolean enabled) {
        given()
                .baseUri(managerUrl)
                .contentType(ContentType.JSON)
                .body([enabled: enabled])
                .put("/cas/${caId}/crl")
                .then().statusCode(HttpStatus.SC_OK)
    }
}
