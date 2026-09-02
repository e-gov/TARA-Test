package ee.ria.tara.step

import ee.ria.tara.Flow
import ee.ria.tara.Requests
import ee.ria.tara.configuration.ConfigHolder
import ee.ria.tara.model.Issuer
import io.qameta.allure.Allure
import io.qameta.allure.Step
import io.restassured.response.Response
import org.apache.http.HttpStatus
import org.bouncycastle.cert.ocsp.BasicOCSPResp
import org.bouncycastle.cert.ocsp.OCSPResp
import org.bouncycastle.cert.ocsp.SingleResp
import spock.util.concurrent.PollingConditions

import java.nio.file.Files

class OcspCrlSteps {

    @Step("Make OCSP request")
    static Response ocspRequest(Flow flow, byte[] body, Issuer issuer) {
        attachOcspRequest(body)
        Response response = Requests.postOcspRequest(flow, body, issuer)
        attachOcspResponse(response.body.asByteArray())
        return response
    }

    @Step("Wait until fallback OCSP reports expected certificate status")
    static SingleResp waitForCertStatus(Flow flow, byte[] ocspRequestBody, Issuer issuer,
                                        Closure<Boolean> statusPredicate) {
        SingleResp singleResp = null
        byte[] lastResponseBody = null
        try {
            new PollingConditions(timeout: 90, delay: 5).eventually {
                Response response = Requests.postOcspRequest(flow, ocspRequestBody, issuer)
                lastResponseBody = response.body.asByteArray()
                singleResp = extractBasicOCSPResp(response).responses[0]
                assert statusPredicate.call(singleResp.certStatus)
            }
        } finally {
            attachOcspRequest(ocspRequestBody)
            if (lastResponseBody != null) {
                attachOcspResponse(lastResponseBody)
            }
        }
        return singleResp
    }

    static BasicOCSPResp extractBasicOCSPResp(Response response) {
        response.then().statusCode(HttpStatus.SC_OK)
        BasicOCSPResp basicResp = extractOcspResp(response).responseObject as BasicOCSPResp
        return basicResp
    }

    static OCSPResp extractOcspResp(Response response) {
        return new OCSPResp(response.then().extract().asByteArray())
    }

    static void attachOcspRequest(byte[] der) {
        Allure.addAttachment("OCSP request", "application/ocsp-request",
                new ByteArrayInputStream(der), ".der")
        printOpensslText("OCSP request", der, "-reqin", "-req_text")
    }

    static void attachOcspResponse(byte[] der) {
        Allure.addAttachment("OCSP response", "application/ocsp-response",
                new ByteArrayInputStream(der), ".der")
        printOpensslText("OCSP response", der, "-respin", "-resp_text")
    }

    // Debug only: shell out to openssl and print the human-readable decode.
    private static void printOpensslText(String label, byte[] der, String inFlag, String textFlag) {
        if (ConfigHolder.testConf.env() != "dev-local") {
            return
        }
        File tmp = File.createTempFile("ocsp", ".der")
        try {
            tmp.bytes = der
            Process p = new ProcessBuilder("openssl", "ocsp", inFlag, tmp.absolutePath, textFlag, "-noverify")
                    .redirectErrorStream(true)
                    .start()
            String text = p.inputStream.text
            p.waitFor()
            println "===== ${label} (openssl) =====\n${text}"
        } catch (Exception e) {
            println "Could not run openssl for ${label}: ${e.message}"
        } finally {
            Files.deleteIfExists(tmp.toPath())
        }
    }
}
