package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.path.json.JsonPath
import io.restassured.response.Response
import spock.lang.Ignore
import spock.lang.Unroll
import spock.lang.IgnoreIf

import static org.hamcrest.Matchers.equalTo
import static org.junit.Assert.assertTrue
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat

@IgnoreIf({ properties['test.deployment.env'] == "idp" })
class OidcMetadataSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    @Ignore()
    @Unroll
    @Feature("/oidc/.well-known/openid-configuration endpoint")
    def "Test configuration request and verify the structure and element coherence compared to TARA1 on response"() {
        expect:
        Response configurationResponse = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        // In adition to typical comparing with TARA1 it is needed to test that not supported features in TARA2 are disabled
        assertThat(configurationResponse, equalTo("TARA1 response"))
    }

    @Ignore()
    @Unroll
    @Feature("oidc/jwks endpoint")
    def "Test jwks requests and verify the structure and element coherence compared to TARA1 on response"() {
        expect:
        JWKSet jwkResponse = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
        // In adition to typical comparing with TARA1 it is needed to test that not supported features in TARA2 are disabled
        assertThat(jwkResponse, equalTo("TARA1 response"))
    }

    @Unroll
    @Feature("OIDC_DISCOVERY_ENDPOINT")
    def "Verify discovery path #path"() {
        expect:
        Response response = Requests.getRequest(flow.oidcService.baseUrl + path)
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())
        assertEquals("Correct issuer", (flow.oidcService.baseUrl.toString() + "/"), response.getBody().jsonPath().get("issuer"))

        where:
        path || statusCode
        "/.well-known/openid-configuration" || 200
        // TARA2-151
        //     "/oidc/.well-known" || 200
        //    "/.well-known" || 200
    }

    @Ignore // TARA2-151
    @Unroll
    @Feature("OIDC_DISCOVERY_CONTENT")
    def "Verify discovery content"() {
        expect:
        JsonPath jsonResponse = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        assertEquals("Correct issuer", (flow.oidcService.baseUrl.toString() + "/"), jsonResponse.get("issuer"))
        List<String> scopesSupported = jsonResponse.getList("scopes_supported")
        def scopeList = ["openid", "idcard", "mid", "smartid"] //, "eidas", "eidasonly", "email", "phone"]
        scopeList.each {
            assertTrue("Scope supported. Contains $it", scopesSupported.contains(it))
        }

        assertEquals("Supported response types", "code", jsonResponse.getList("response_types_supported")[0])
        assertEquals("Supported subject types", "public", jsonResponse.getList("subject_types_supported")[0])
        assertEquals("Supported claim types", "normal", jsonResponse.getList("claim_types_supported")[0])

        List<String> claimsSupported = jsonResponse.getList("claims_supported")
        // TODO TARA2-151
        def claimsList = ["sub", "profile_attributes.given_name", "profile_attributes.family_name", "profile_attributes.date_of_birth"]
        claimsList.add("profile_attributes.represents_legal_person.name")
        claimsList.add("profile_attributes.represents_legal_person.registry_code")
//        claimsList.add("email")
//        claimsList.add("email_verified")
//        claimsList.add("phonenumber")
//        claimsList.add("phonenumber_verified")
        claimsList.each {
            assertTrue("Claim supported. Contains $it", claimsSupported.contains(it))
        }
        assertEquals("Supported grant types", "authorization_code", jsonResponse.getList("grant_types_supported")[0])
        assertEquals("Supported alg values", "RS256", jsonResponse.getList("id_token_signing_alg_values_supported")[0])
        List<String> localesSupported = jsonResponse.getList("ui_locales_supported")
        def localesList = ["et", "en", "ru"]
        localesList.each {
            assertTrue("Locale $it supported", localesSupported.contains(it))
        }
        // TARA2-151
//        assertEquals("Correct token endpoint", (flow.oidcService.baseUrl + "/oidc/token"), jsonResponse.getString("token_endpoint"))
//        assertEquals("Correct userinfo endpoint", (flow.oidcService.baseUrl + "/oidc/profile"), jsonResponse.getString("userinfo_endpoint"))
//        assertEquals("Correct authorization endpoint", (flow.oidcService.baseUrl + "/oidc/authorization"), jsonResponse.getString("userinfo_endpoint"))
//        assertEquals("Correct jwks uri", (flow.oidcService.baseUrl + "/oidc/jwks"), jsonResponse.getString("jwks_uri"))
    }


}
