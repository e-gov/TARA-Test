package ee.ria.tara.ocspcrl

import ee.ria.tara.TaraSpecification
import ee.ria.tara.Utils
import ee.ria.tara.configuration.ConfigHolder
import ee.ria.tara.model.Issuer
import ee.ria.tara.request.RequestData
import ee.ria.tara.step.EidTestPkiClient
import ee.ria.tara.step.OcspCrlSteps
import ee.ria.tara.util.PersonCodeGenerator
import io.restassured.response.Response
import org.apache.http.HttpStatus
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x500.style.IETFUtils
import org.bouncycastle.asn1.x509.CRLReason
import org.bouncycastle.cert.ocsp.*
import org.bouncycastle.operator.ContentVerifierProvider
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import spock.lang.Tag

import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*

class FallbackOcspSpec extends TaraSpecification {

    def "Fallback OCSP request returns GOOD"() {
        given:
        byte[] ocspRequestBody = RequestData.ocspRequestDefaultBody(true)

        when:
        Response response = OcspCrlSteps.ocspRequest(flow, ocspRequestBody, Issuer.TEST_OF_ESTEID2018)

        then:
        response.then().statusCode(HttpStatus.SC_OK)

        byte[] ocspResponseBytes = response.then().extract().asByteArray()
        OCSPResp ocspResponse = new OCSPResp(ocspResponseBytes)
        assertThat(ocspResponse.status, is(OCSPResp.SUCCESSFUL))

        BasicOCSPResp basicResp = ocspResponse.responseObject as BasicOCSPResp
        assertThat(basicResp.responses.size(), is(1))
        SingleResp singleResp = basicResp.responses[0]
        assertThat(singleResp.certStatus, is(CertificateStatus.GOOD))
    }

    def "Fallback OCSP response has valid signature"() {
        given:
        X509Certificate ocspIssuerCert = Utils.loadCertificate(ConfigHolder.testConf.ocspResponderCertPath())
        byte[] ocspRequestBody = RequestData.ocspRequestDefaultBody(true)

        when:
        Response response = OcspCrlSteps.ocspRequest(flow, ocspRequestBody, Issuer.TEST_OF_ESTEID2018)

        then:
        BasicOCSPResp basicResp = OcspCrlSteps.extractBasicOCSPResp(response)

        // Verify signature
        ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                .build(ocspIssuerCert.publicKey)
        assertThat(basicResp.isSignatureValid(verifierProvider), is(true))

        // exactly the signing certificate is embedded, and the responder is identified by its name
        assertThat(basicResp.certs.length, is(1))
        assertThat(basicResp.responderId, is(new RespID(basicResp.certs[0].subject)))

        X500Name responderName = basicResp.responderId.toASN1Primitive().name
        String cn = IETFUtils.valueToString(responderName.getRDNs(BCStyle.CN)[0].first.value)
        assertThat(cn, is(flow.ocspCrlService.responderSubjectCN))
    }

    def "Fallback OCSP response has valid nonce"() {
        given:
        byte[] nonce = new byte[16]
        new SecureRandom().nextBytes(nonce)
        byte[] ocspRequestBody = RequestData.ocspRequestDefaultBody(true, nonce)

        when:
        Response response = OcspCrlSteps.ocspRequest(flow, ocspRequestBody, Issuer.TEST_OF_ESTEID2018)

        then:
        BasicOCSPResp basicResp = OcspCrlSteps.extractBasicOCSPResp(response)

        // Verify nonce
        byte[] returnedNonce = ASN1OctetString.getInstance(
                basicResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).extnValue.octets
        ).octets
        assertThat(returnedNonce, is(nonce))
    }

    def "Fallback OCSP response has valid timestamps"() {
        given:
        byte[] ocspRequestBody = RequestData.ocspRequestDefaultBody(true)

        when:
        Response response = OcspCrlSteps.ocspRequest(flow, ocspRequestBody, Issuer.TEST_OF_ESTEID2018)

        then:
        BasicOCSPResp basicResp = OcspCrlSteps.extractBasicOCSPResp(response)
        SingleResp singleResp = basicResp.responses[0]
        Instant now = Instant.now()

        // producedAt is recent
        assertThat(Duration.between(basicResp.producedAt.toInstant(), now).abs(), lessThan(Duration.ofSeconds(60)))

        // TEST of ESTEID2018 CRL is reissued ~every 11.5h and valid ~7 days
        Instant thisUpdate = singleResp.thisUpdate.toInstant()
        Instant nextUpdate = singleResp.nextUpdate.toInstant()
        assertThat(thisUpdate, greaterThan(now - Duration.ofHours(12)))
        assertThat(thisUpdate, lessThan(now))
        assertThat(nextUpdate, greaterThan(now + Duration.ofDays(6)))
        assertThat(nextUpdate, lessThan(now + Duration.ofDays(8)))
    }

    def "Fallback OCSP request returns UNKNOWN for a certificate from a different issuer"() {
        given: "an OCSP request for cert issued by TEST of ESTEID2018"
        byte[] ocspRequestBody = RequestData.ocspRequestDefaultBody(true)

        when: "the request is posted to the Test ESTEID2025 chain"
        Response response = OcspCrlSteps.ocspRequest(flow, ocspRequestBody, Issuer.TEST_ESTEID2025)

        then: "the fallback OCSP reports Unknown status"
        BasicOCSPResp basicResp = OcspCrlSteps.extractBasicOCSPResp(response)
        assertThat(basicResp.responses.size(), is(1))
        assertThat(basicResp.responses[0].certStatus, is(instanceOf(UnknownStatus)))
    }

    @Tag("ee-eid-test-pki")
    def "Fallback OCSP request returns REVOKED after certificate is revoked"() {
        given: "a freshly issued community ID-card certificate"
        String caId = "community-esteid2025"
        String code = PersonCodeGenerator.generateEstonianPersonCode()
        EidTestPkiClient.issueAuthCert(caId, code, "TESTER", "TESTING")

        and: "an OCSP request built for its leaf + issuer certificate"
        X509Certificate[] chain = Utils.getCertificateChainFromKeystore(
                EidTestPkiClient.getAuthCertP12(caId, code, "1234"), "1234")
        byte[] ocspRequestBody = RequestData.ocspRequestBody(chain, true)

        when: "the certificate is revoked with the given reason"
        EidTestPkiClient.setAuthCertStatus(caId, code, "revoked", reasonName)

        then: "the fallback OCSP eventually (after the CRL refresh) reports REVOKED with that reason"
        // TODO: If possible, replace with triggering CRL loading, otherwise consider setting conf to smaller interval.
        SingleResp singleResp = OcspCrlSteps.waitForCertStatus(
                flow, ocspRequestBody, Issuer.COMMUNITY_ESTEID2025, { it instanceof RevokedStatus })
        RevokedStatus revoked = singleResp.certStatus as RevokedStatus
        assertThat(revoked.revocationTime, notNullValue())
        assertThat(revoked.hasRevocationReason(), is(true))
        assertThat(revoked.revocationReason, is(expectedReason))

        where:
        reasonName        | expectedReason
        "keyCompromise"   | CRLReason.keyCompromise
        "certificateHold" | CRLReason.certificateHold
    }
}
