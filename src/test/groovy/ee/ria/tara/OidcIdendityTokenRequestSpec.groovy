package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.hamcrest.Matchers

import spock.lang.IgnoreIf
import spock.lang.Ignore
import spock.lang.Unroll

import static org.hamcrest.Matchers.equalTo
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat
import static org.junit.Assert.assertTrue

@IgnoreIf({ properties['test.deployment.env'] == "idp" })
class OidcIdendityTokenRequestSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Ignore()
    @Unroll
    @Feature("https://e-gov.github.io/TARA-Doku/TechnicalSpecification#43-identity-token-request")
    def "Test the identity token request parameters and verify response structure and coherence with TARA 1"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response midAuthResponse = Steps.authenticateWithMid(flow,"60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        // In addition to request structure validation, it is needed to verify the security elements, error cases...
        assertThat(tokenResponse, equalTo("TARA1 generated response"))
    }

    @Unroll
    @Feature("OIDC_ID_TOKEN")
    def "Verify ID token response"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response midAuthResponse = Steps.authenticateWithMid(flow,"60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        assertEquals("Correct token_type value", "bearer", tokenResponse.body().jsonPath().getString("token_type"))
        assertEquals("Correct scope value", "openid", tokenResponse.body().jsonPath().getString("scope"))
        assertTrue("Access token element exists", tokenResponse.body().jsonPath().getString("access_token").size() > 32)
        assertTrue("Expires in element exists", tokenResponse.body().jsonPath().getInt("expires_in") > 60)
        assertTrue("ID token element exists", tokenResponse.body().jsonPath().getString("id_token").size() > 1000)
    }

    @Unroll
    @Feature("OIDC_ID_TOKEN")
    def "Verify ID token mandatory elements"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        String idCode = "60001017716"
        String phoneNo = "69100366"
        Response midAuthResponse = Steps.authenticateWithMid(flow, idCode, phoneNo)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        assertEquals("Correct token_type value", "bearer", tokenResponse.body().jsonPath().getString("token_type"))
        assertEquals("Correct scope value", "openid", tokenResponse.body().jsonPath().getString("scope"))
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertTrue("Correct jti claim exists", claims.getJWTID().size() > 35)
        assertThat("Correct issuer claim", claims.getIssuer(), equalTo(flow.openIdServiceConfiguration.get("issuer")))
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClient.clientId))
        Date date = new Date()
        assertThat("Expected current: " + date + " to be after nbf: " + claims.getNotBeforeTime(), date.after(claims.getNotBeforeTime()), Matchers.is(true))
        // 10 seconds
        assertTrue("Correct iat claim", Math.abs(date.getTime() - claims.getDateClaim("iat").getTime()) < 10000L)
        assertThat("Correct subject claim", claims.getSubject(), equalTo("EE" + idCode))

        assertThat("Correct date of birth", claims.getJSONObjectClaim("profile_attributes").get("date_of_birth"),  equalTo("2000-01-01"))
        assertThat("Correct given name", claims.getJSONObjectClaim("profile_attributes").get("given_name"),  equalTo("ONE"))
        assertThat("Correct family name", claims.getJSONObjectClaim("profile_attributes").get("family_name"),  equalTo("TESTNUMBER"))
        assertThat("Correct amr value", claims.getStringArrayClaim("amr")[0].toString(), Matchers.oneOf("smartid", "eIDAS", "idcard", "mID"))
        // TODO TARA2-182
        // assertThat("Correct state value", claims.getStringClaim("state"), equalTo(flow.getState()))
        assertThat("Correct LoA level", claims.getStringClaim("acr"), equalTo("high"))
        assertTrue("Correct at_hash claim exists", claims.getStringClaim("at_hash").size()  > 20)
    }

    @Unroll
    @Feature("OIDC_ID_TOKEN")
    def "Verify ID token with optional elements by phone scope"() {
        expect:
        String scopeList = "openid phone"
        Steps.startAuthenticationInTara(flow, scopeList)
        String idCode = "60001017716"
        String phoneNo = "69100366"
        Response midAuthResponse = Steps.authenticateWithMid(flow, idCode, phoneNo)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        assertEquals("Correct token_type value", "bearer", tokenResponse.body().jsonPath().getString("token_type"))
        assertEquals("Correct scope value", scopeList, tokenResponse.body().jsonPath().getString("scope"))
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat("Correct subject claim", claims.getSubject(), equalTo("EE" + idCode))
        assertThat("Phone_number claim exists", claims.getStringClaim("phone_number"), equalTo("+372" + phoneNo))
        assertThat("Phone_number_verified claim exists", claims.getBooleanClaim("phone_number_verified"), equalTo(true))
    }

    @Unroll
    @Feature("OIDC_ID_TOKEN")
    def "Verify ID token with optional elements by email scope"() {
        expect:
        String scopeList = "openid email"
        Steps.startAuthenticationInTara(flow, scopeList)
        Response idCardAuthResponse = Steps.authenticateWithIdCard(flow, "src/test/resources/joeorg-auth.pem")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, idCardAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        assertEquals("Correct token_type value", "bearer", tokenResponse.body().jsonPath().getString("token_type"))
        assertEquals("Correct scope value", scopeList, tokenResponse.body().jsonPath().getString("scope"))
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat("Correct subject claim", claims.getSubject(), equalTo("EE38001085718"))
        assertThat("Phone_number claim exists", claims.getStringClaim("email"), equalTo("38001085718@eesti.ee"))
        assertThat("Phone_number_verified claim exists", claims.getBooleanClaim("email_verified"), equalTo(false))
    }
}
