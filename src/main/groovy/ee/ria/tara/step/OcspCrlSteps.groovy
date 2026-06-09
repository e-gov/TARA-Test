package ee.ria.tara.step

import ee.ria.tara.configuration.ConfigHolder
import io.qameta.allure.Allure
import io.restassured.response.Response
import org.apache.http.HttpStatus
import org.bouncycastle.cert.ocsp.BasicOCSPResp
import org.bouncycastle.cert.ocsp.OCSPResp

import java.nio.file.Files

class OcspCrlSteps {

    static BasicOCSPResp extractBasicOCSPResp(Response response) {
        response.then().statusCode(HttpStatus.SC_OK)

        OCSPResp ocspResponse = new OCSPResp(response.then().extract().asByteArray())
        BasicOCSPResp basicResp = ocspResponse.responseObject as BasicOCSPResp
        return basicResp
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
