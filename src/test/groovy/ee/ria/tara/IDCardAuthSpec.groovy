package ee.ria.tara

import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.hamcrest.Matchers

import static org.hamcrest.Matchers.equalTo
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat
import spock.lang.Unroll


class IDCardAuthSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("ESTEID_AUTH_ENDPOINT")
    def "Init ID-Card authentication"() {
        expect:
        String certificate = Utils.getCertificateAsString("src/test/resources/joeorg-auth.pem")
        Response initClientAuthenticationSession = Steps.initAuthenticationSession(flow)
        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(headersMap, "XCLIENTCERTIFICATE", certificate)
        Response response = Requests.idCardAuthentication(flow, headersMap)
        assertThat("Correct response", response.body().jsonPath().get("status").toString(), equalTo("COMPLETED"))
    }

    @Unroll
    @Feature("IDCARD_AUTH_SUCCESSFUL")
    def "Authenticate with ID-Card"() {
        expect:
        String certificate = Utils.getCertificateAsString("src/test/resources/joeorg-auth.pem")
        Response initClientAuthenticationSession = Steps.initAuthenticationSession(flow)
        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(headersMap, "XCLIENTCERTIFICATE", certificate)
        Response response = Requests.idCardAuthentication(flow, headersMap)
        assertThat("Correct response", response.body().jsonPath().get("status").toString(), equalTo("COMPLETED"))
        Response acceptResponse = Requests.followRedirectWithSessionId(flow, REQUEST_TYPE_POST, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 302, acceptResponse.statusCode())
        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        assertEquals("Correct HTTP status code is returned", 302, oidcServiceResponse.statusCode())

        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        assertEquals("Correct HTTP status code is returned", 302, consentResponse.statusCode())
        Response oidcserviceResponse = Steps.followRedirectWithCookies(flow, consentResponse, flow.oidcService.cookies)
        assertEquals("Correct HTTP status code is returned", 302, oidcserviceResponse.statusCode())

        Response webTokenResponse = Steps.followRedirectWithCookies(flow, oidcserviceResponse, flow.oidcClient.cookies)
        assertEquals("Correct HTTP status code is returned", 200, webTokenResponse.statusCode())
        Map<String, String> webToken = webTokenResponse.body().jsonPath().getMap("\$.")
        JWTClaimsSet claims = TokenUtils.verifyTokenAndReturnSignedJwtObject(webToken.get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClient.clientId))
        assertThat(claims.getSubject(), equalTo("EE38001085718"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("JAAK-KRISTJAN"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("family_name"), equalTo("JÕEORG"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("date_of_birth"), equalTo("1980-01-08"))
        assertThat(claims.getClaim("amr")[0].toString(), equalTo("idcard"))
        assertThat(claims.getClaim("acr"), equalTo("high"))
    }
}
