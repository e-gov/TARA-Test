package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Ignore

import static org.hamcrest.Matchers.equalTo
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat
import spock.lang.Unroll


class IDCardAuthSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Unroll
    @Feature("ESTEID_AUTH_ENDPOINT")
    def "Init ID-Card authentication"() {
        expect:
        String certificate = Utils.getCertificateAsString("src/test/resources/joeorg-auth.pem")
        Response initClientAuthenticationSession = Steps.startAuthenticationInTara(flow)
        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(headersMap, "XCLIENTCERTIFICATE", certificate)
        Response response = Requests.idCardAuthentication(flow, headersMap)
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())
        assertThat("Correct response", response.body().jsonPath().get("status").toString(), equalTo("COMPLETED"))
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
    }

    @Unroll
    @Feature("ESTEID_AUTH_ENDPOINT")
    @Feature("CERTIFICATE_IS_VALID")
    @Feature("REJECT_EXPIRED_CERTS")
    def "Init ID-Card authentication with expired certificate"() {
        expect:
        String certificate = Utils.getCertificateAsString("src/test/resources/expired-cert.pem")
        Response initClientAuthenticationSession = Steps.startAuthenticationInTara(flow)
        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(headersMap, "XCLIENTCERTIFICATE", certificate)
        Response response = Requests.idCardAuthentication(flow, headersMap)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertThat("Correct response", response.body().jsonPath().get("status").toString(), equalTo("ERROR"))
        assertThat("Correct error message", response.body().jsonPath().get("errorMessage").toString(), equalTo("Teie sertifikaadid ei kehti."))
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
    }

    @Unroll
    @Feature("IDCARD_AUTH_SUCCESSFUL")
    def "Authenticate with ID-Card"() {
        expect:
        String certificate = Utils.getCertificateAsString("src/test/resources/joeorg-auth.pem")
        Response initClientAuthenticationSession = Steps.startAuthenticationInTara(flow)
        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(headersMap, "XCLIENTCERTIFICATE", certificate)
        Response response = Requests.idCardAuthentication(flow, headersMap)
        assertThat("Correct response", response.body().jsonPath().get("status").toString(), equalTo("COMPLETED"))
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 302, acceptResponse.statusCode())
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        assertEquals("Correct HTTP status code is returned", 302, oidcServiceResponse.statusCode())

        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        assertEquals("Correct HTTP status code is returned", 200, consentResponse.statusCode())
        Response consentConfirmResponse = Steps.submitConsent(flow, true)
        assertEquals("Correct HTTP status code is returned", 302, consentConfirmResponse.statusCode())
        Response oidcserviceResponse = Steps.followRedirectWithCookies(flow, consentConfirmResponse, flow.oidcService.cookies)
        assertEquals("Correct HTTP status code is returned", 302, oidcserviceResponse.statusCode())
        String authorizationCode = Utils.getParamValueFromResponseHeader(oidcserviceResponse, "code")
        Response tokenResponse = Requests.getWebToken(flow, authorizationCode)

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClient.clientId))
        assertThat(claims.getSubject(), equalTo("EE38001085718"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("JAAK-KRISTJAN"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("family_name"), equalTo("JÕEORG"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("date_of_birth"), equalTo("1980-01-08"))
        assertThat(claims.getClaim("amr")[0].toString(), equalTo("idcard"))
        assertThat(claims.getClaim("acr"), equalTo("high"))
    }

    @Ignore // TARA2-178
    @Unroll
    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Verify ID-Card authentication response headers"() {
        expect:
        String certificate = Utils.getCertificateAsString("src/test/resources/joeorg-auth.pem")
        Response initClientAuthenticationSession = Steps.startAuthenticationInTara(flow)
        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(headersMap, "XCLIENTCERTIFICATE", certificate)
        Response response = Requests.idCardAuthentication(flow, headersMap)
        Steps.verifyResponseHeaders(response)
    }

    @Unroll
    @Feature("ESTEID_AUTH_ENDPOINT")
    @Feature("ESTEID_INIT")
    def "Init ID-Card authentication with invalid session"() {
        expect:
        String certificate = Utils.getCertificateAsString("src/test/resources/joeorg-auth.pem")
        Response initClientAuthenticationSession = Steps.startAuthenticationInTara(flow)
        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(headersMap, "XCLIENTCERTIFICATE", certificate)
        flow.setSessionId("123456789")
        Response response = Requests.idCardAuthentication(flow, headersMap)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }

    @Unroll
    @Feature("ESTEID_AUTH_ENDPOINT")
    @Feature("ESTEID_INIT")
    def "Init ID-Card authentication with missing session cookie"() {
        expect:
        String certificate = Utils.getCertificateAsString("src/test/resources/joeorg-auth.pem")
        Response initClientAuthenticationSession = Steps.startAuthenticationInTara(flow)
        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(headersMap, "XCLIENTCERTIFICATE", certificate)
        Response response = Requests.idCardAuthenticationWithoutSession(flow, headersMap)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }
}
