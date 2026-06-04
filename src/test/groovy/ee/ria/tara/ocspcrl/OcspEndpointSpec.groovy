package ee.ria.tara.ocspcrl


import ee.ria.tara.TaraSpecification
import ee.ria.tara.model.Issuer
import ee.ria.tara.request.RequestData
import io.restassured.RestAssured
import io.restassured.http.Method
import io.restassured.response.Response
import org.apache.http.HttpStatus

import static io.restassured.RestAssured.given
import static io.restassured.config.EncoderConfig.encoderConfig

class OcspEndpointSpec extends TaraSpecification {


    def "Request OCSP from CRL with invalid method: #requestType"() {
        given:
        byte[] ocspRequestBody = RequestData.ocspRequestDefaultBody(true)

        when:
        Response response = given()
                .config(RestAssured.config()
                        .encoderConfig(encoderConfig()
                                .appendDefaultContentCharsetToContentTypeIfUndefined(false)))
                .contentType("application/ocsp-request")
                .accept("application/ocsp-response")
                .body(ocspRequestBody)
                .request(requestType, flow.ocspCrlService.ocspUrl + "/" + Issuer.TEST_OF_ESTEID2018.path)

        then:
        response.then().statusCode(HttpStatus.SC_METHOD_NOT_ALLOWED)

        where:
        requestType   | _
        Method.GET    | _
        Method.PUT    | _
        Method.PATCH  | _
        Method.DELETE | _
    }
}
