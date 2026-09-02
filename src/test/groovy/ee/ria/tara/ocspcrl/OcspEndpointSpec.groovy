package ee.ria.tara.ocspcrl

import ee.ria.tara.Requests
import ee.ria.tara.TaraSpecification
import ee.ria.tara.model.Issuer
import ee.ria.tara.request.RequestData
import io.restassured.http.Method
import io.restassured.response.Response
import org.apache.http.HttpStatus

class OcspEndpointSpec extends TaraSpecification {


    def "Fallback OCSP request with invalid method: '#requestType' returns 'method not allowed'"() {
        given:
        byte[] ocspRequestBody = RequestData.ocspRequestDefaultBody(true)

        when:
        Response response = Requests.postOcspRequest(flow, requestType, Issuer.TEST_OF_ESTEID2018.path,
                "application/ocsp-request", ocspRequestBody)

        then:
        response.then().statusCode(HttpStatus.SC_METHOD_NOT_ALLOWED)

        where:
        requestType   | _
        Method.GET    | _
        Method.PUT    | _
        Method.PATCH  | _
        Method.DELETE | _
    }

    def "Fallback OCSP request for unconfigured certificate chain returns 'not found'"() {
        given:
        byte[] ocspRequestBody = RequestData.ocspRequestDefaultBody(true)

        when: "the request is posted to a chain id that is not configured in the service"
        Response response = Requests.postOcspRequest(flow, Method.POST, "not_configured_chain",
                "application/ocsp-request", ocspRequestBody)

        then:
        response.then().statusCode(HttpStatus.SC_NOT_FOUND)
    }

    def "Fallback OCSP request with unsupported content type: '#contentType' returns 'unsupported media type'"() {
        given:
        byte[] ocspRequestBody = RequestData.ocspRequestDefaultBody(true)

        when:
        Response response = Requests.postOcspRequest(flow, Method.POST, Issuer.TEST_OF_ESTEID2018.path,
                contentType, ocspRequestBody)

        then:
        response.then().statusCode(HttpStatus.SC_UNSUPPORTED_MEDIA_TYPE)

        where:
        contentType << ["application/json", "application/octet-stream", "text/plain"]
    }

    def "Fallback OCSP request with invalid body returns 'bad request'"() {
        given: "a body that is not parseable as DER"
        byte[] notAnOcspRequest = "this is not an OCSP request".bytes

        when:
        Response response = Requests.postOcspRequest(flow, Method.POST, Issuer.TEST_OF_ESTEID2018.path,
                "application/ocsp-request", notAnOcspRequest)

        then:
        response.then().statusCode(HttpStatus.SC_BAD_REQUEST)
    }

    def "Fallback OCSP request exceeding the 10KB body size limit returns 'bad request'"() {
        given: "a structurally valid OCSP request padded past MAX_BODY_SIZE with an oversized nonce"
        byte[] oversizedBody = RequestData.ocspRequestDefaultBody(true, new byte[10 * 1024])
        assert oversizedBody.length > 10 * 1024

        when:
        Response response = Requests.postOcspRequest(flow, Method.POST, Issuer.TEST_OF_ESTEID2018.path,
                "application/ocsp-request", oversizedBody)

        then: "only the size check can reject it, since the request itself is well-formed"
        response.then().statusCode(HttpStatus.SC_BAD_REQUEST)
    }
}
