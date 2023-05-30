package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.greaterThan
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.lessThan

class OidcIdentityTokenRequestSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Feature("OIDC_ID_TOKEN")
    def "Verify ID token response"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Response midAuthResponse = Steps.authenticateWithMid(flow, "60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)

        then:
        assertThat("Correct token_type value", tokenResponse.jsonPath().getString("token_type"), is("bearer"))
        assertThat("Correct scope value", tokenResponse.jsonPath().getString("scope"), is("openid"))
        assertThat("Access_token element exists", tokenResponse.jsonPath().getString("access_token").size(), greaterThan(32))
        assertThat("Expires_in element exists", tokenResponse.jsonPath().getInt("expires_in"), greaterThan(60))
        assertThat("Id_token element exists", tokenResponse.jsonPath().getString("id_token").size(), greaterThan(1000))
    }

    @Feature("OIDC_ID_TOKEN")
    def "Verify ID token mandatory elements"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Response midAuthResponse = Steps.authenticateWithMid(flow, "60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Jti claim exists", claims.getJWTID().size(), is(36))
        assertThat("Correct issuer claim", claims.issuer, is(flow.openIdServiceConfiguration.get("issuer")))
        assertThat("Correct audience", claims.audience[0], is(flow.oidcClientPublic.clientId))
        Date date = new Date()
        assertThat("Expected current: " + date + " to be after nbf: " + claims.notBeforeTime, date.after(claims.notBeforeTime), is(true))
        assertThat("Iat claim exists", Math.abs(date.time - claims.getDateClaim("iat").time), lessThan(10000L))
        assertThat("Correct subject claim", claims.subject, is("EE60001017716"))
        assertThat("Correct date of birth", claims.getJSONObjectClaim("profile_attributes")["date_of_birth"], is("2000-01-01"))
        assertThat("Correct given name", claims.getJSONObjectClaim("profile_attributes")["given_name"], is("ONE"))
        assertThat("Correct family name", claims.getJSONObjectClaim("profile_attributes")["family_name"], is("TESTNUMBER"))
        assertThat("Correct amr value", claims.getStringArrayClaim("amr")[0].toString(), is("mID"))
        assertThat("Correct state value", claims.getClaim("state"), is(flow.state))
        assertThat("Correct LoA level", claims.getClaim("acr"), is("high"))
        assertThat("At_hash claim exists", claims.getStringClaim("at_hash").size(), greaterThan(20))
    }

    @Feature("OIDC_ID_TOKEN")
    def "Verify ID token with optional elements by phone scope"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid phone")
        Response midAuthResponse = Steps.authenticateWithMid(flow, "60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct scope value", tokenResponse.jsonPath().getString("scope"), is("openid phone"))
        assertThat("Correct subject claim", claims.subject, is("EE60001017716"))
        assertThat("Phone_number claim exists", claims.getStringClaim("phone_number"), is("+37269100366"))
        assertThat("Phone_number_verified claim exists", claims.getBooleanClaim("phone_number_verified"), is(true))
    }

    @Feature("OIDC_ID_TOKEN")
    def "Verify ID token with optional elements by email scope"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid email")

        when:
        Response tokenResponse = Steps.authenticateWithWebeID(flow)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct scope value", tokenResponse.jsonPath().getString("scope"), is("openid email"))
        assertThat("Correct subject claim", claims.getSubject(), is("EE38001085718"))
        assertThat("Phone_number claim exists", claims.getStringClaim("email"), is("jaak-kristjan.joeorg@eesti.ee"))
        assertThat("Phone_number_verified claim exists", claims.getBooleanClaim("email_verified"), is(false))
    }
}