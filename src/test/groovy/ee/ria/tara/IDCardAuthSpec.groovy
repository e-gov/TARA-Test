package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response


import static org.hamcrest.Matchers.equalTo
import static org.junit.jupiter.api.Assertions.*
import static org.hamcrest.MatcherAssert.assertThat
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
        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        assertThat("Correct response", response.body().jsonPath().get("status").toString(), equalTo("COMPLETED"))
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
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
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertThat("Correct response", response.body().jsonPath().get("status").toString(), equalTo("ERROR"))
        assertThat("Correct error message", response.body().jsonPath().get("message").toString(), equalTo("ID-kaardi sertifikaadid ei kehti."))
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
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
        assertEquals(302, acceptResponse.statusCode(), "Correct HTTP status code is returned")
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        assertEquals(302, oidcServiceResponse.statusCode(), "Correct HTTP status code is returned")

        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)

        if (consentResponse.getStatusCode() == 200) {
            consentResponse = Steps.submitConsent(flow, true)
            assertEquals(302, consentResponse.statusCode(), "Correct HTTP status code is returned")
            Steps.verifyResponseHeaders(consentResponse)
        }

        assertEquals(302, consentResponse.statusCode(), "Correct HTTP status code is returned")
        Response oidcserviceResponse = Steps.followRedirectWithCookies(flow, consentResponse, flow.oidcService.cookies)
        assertEquals(302, oidcserviceResponse.statusCode(), "Correct HTTP status code is returned")
        String authorizationCode = Utils.getParamValueFromResponseHeader(oidcserviceResponse, "code")
        Response tokenResponse = Requests.getWebToken(flow, authorizationCode)
        assertEquals(200, tokenResponse.statusCode(), "Correct HTTP status code is returned")
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClient.clientId))
        assertThat(claims.getSubject(), equalTo("EE38001085718"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("JAAK-KRISTJAN"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("family_name"), equalTo("JÕEORG"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("date_of_birth"), equalTo("1980-01-08"))
        assertThat(claims.getClaim("amr")[0].toString(), equalTo("idcard"))
        assertThat(claims.getClaim("acr"), equalTo("high"))
    }

    @Unroll
    @Feature("IDCARD_AUTH_SUCCESSFUL")
    def "Authenticate with ID-Card. Esteid 2015 chain certificate"() {
        expect:
        String certificate = Utils.getCertificateAsString("src/test/resources/Mari-Liis-Esteid-2015_auth.pem")
        Response initClientAuthenticationSession = Steps.startAuthenticationInTara(flow)
        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(headersMap, "XCLIENTCERTIFICATE", certificate)
        Response response = Requests.idCardAuthentication(flow, headersMap)
        assertThat("Correct response", response.body().jsonPath().get("status").toString(), equalTo("COMPLETED"))
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals(302, acceptResponse.statusCode(), "Correct HTTP status code is returned")
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        assertEquals(302, oidcServiceResponse.statusCode(), "Correct HTTP status code is returned")

        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)

        if (consentResponse.getStatusCode() == 200) {
            consentResponse = Steps.submitConsent(flow, true)
            assertEquals(302, consentResponse.statusCode(), "Correct HTTP status code is returned")
            Steps.verifyResponseHeaders(consentResponse)
        }

        assertEquals(302, consentResponse.statusCode(), "Correct HTTP status code is returned")
        Response oidcserviceResponse = Steps.followRedirectWithCookies(flow, consentResponse, flow.oidcService.cookies)
        assertEquals(302, oidcserviceResponse.statusCode(), "Correct HTTP status code is returned")
        String authorizationCode = Utils.getParamValueFromResponseHeader(oidcserviceResponse, "code")
        Response tokenResponse = Requests.getWebToken(flow, authorizationCode)
        assertEquals(200, tokenResponse.statusCode(), "Correct HTTP status code is returned")
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClient.clientId))
        assertThat(claims.getSubject(), equalTo("EE47101010033"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("MARI-LIIS"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("family_name"), equalTo("MÄNNIK"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("date_of_birth"), equalTo("1971-01-01"))
        assertThat(claims.getClaim("amr")[0].toString(), equalTo("idcard"))
        assertThat(claims.getClaim("acr"), equalTo("high"))
    }

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
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertEquals("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"), "Correct error message is returned")
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
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertEquals("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"), "Correct error message is returned")
    }
}
