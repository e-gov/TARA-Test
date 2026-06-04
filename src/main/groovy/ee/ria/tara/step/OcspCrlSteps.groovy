package ee.ria.tara.step

import io.restassured.response.Response
import org.apache.http.HttpStatus
import org.bouncycastle.cert.ocsp.BasicOCSPResp
import org.bouncycastle.cert.ocsp.OCSPResp

class OcspCrlSteps {

    static BasicOCSPResp extractBasicOCSPResp(Response response) {
        response.then().statusCode(HttpStatus.SC_OK)

        OCSPResp ocspResponse = new OCSPResp(response.then().extract().asByteArray())
        BasicOCSPResp basicResp = ocspResponse.responseObject as BasicOCSPResp
        return basicResp
    }
}
