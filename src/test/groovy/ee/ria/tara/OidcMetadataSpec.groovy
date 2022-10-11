package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.path.json.JsonPath
import io.restassured.response.Response
import spock.lang.Unroll

import static org.junit.jupiter.api.Assertions.*

class OidcMetadataSpec extends TaraSpecification {
    Flow flow = new Flow(props)
    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("OIDC_DISCOVERY_ENDPOINT")
    def "Verify discovery path #path"() {
        expect:
        Response response = Requests.getRequest(flow.oidcService.baseUrl + path)
        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals((flow.oidcService.baseUrl.toString()), response.getBody().jsonPath().get("issuer"), "Correct issuer")

        where:
        path || statusCode
        "/.well-known/openid-configuration" || 200
        "/.well-known" || 200
        "/oidc/.well-known/openid-configuration" || 200
        "/oidc/.well-known" || 200
    }

    @Unroll
    @Feature("OIDC_DISCOVERY_CONTENT")
    def "Verify discovery content"() {
        expect:
        JsonPath jsonResponse = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        assertEquals((flow.oidcService.baseUrl.toString()), jsonResponse.get("issuer"), "Correct issuer")
        List<String> scopesSupported = jsonResponse.getList("scopes_supported")
        def scopeList = ["openid", "idcard", "mid", "smartid", "email", "phone"] //, "eidas", "eidasonly"]
        scopeList.each {
            assertTrue(scopesSupported.contains(it), "Scope supported. Contains $it")
        }

        assertEquals("code", jsonResponse.getList("response_types_supported")[0], "Supported response types")
        assertEquals("public", jsonResponse.getList("subject_types_supported")[0], "Supported subject types")
        assertEquals("normal", jsonResponse.getList("claim_types_supported")[0], "Supported claim types")

        List<String> claimsSupported = jsonResponse.getList("claims_supported")
        def claimsList = ["sub", "given_name", "family_name", "date_of_birth"]
        claimsList.add("represents_legal_person.name")
        claimsList.add("represents_legal_person.registry_code")
        claimsList.add("email")
        claimsList.add("email_verified")
        claimsList.add("phonenumber")
        claimsList.add("phonenumber_verified")
        claimsList.each {
            assertTrue(claimsSupported.contains(it), "Claim supported. Contains $it")
        }
        assertEquals("authorization_code", jsonResponse.getList("grant_types_supported")[0], "Supported grant types")
        assertEquals("RS256", jsonResponse.getList("id_token_signing_alg_values_supported")[0], "Supported alg values")
        List<String> localesSupported = jsonResponse.getList("ui_locales_supported")
        def localesList = ["et", "en", "ru"]
        localesList.each {
            assertTrue(localesSupported.contains(it), "Locale $it supported")
        }
        // TARA2-151 , TARA2-219
        assertEquals((flow.oidcService.baseUrl + "/oidc/token").toString(), jsonResponse.getString("token_endpoint"), "Correct token endpoint")
        assertEquals((flow.oidcService.baseUrl + "/oidc/profile").toString(), jsonResponse.getString("userinfo_endpoint"), "Correct userinfo endpoint")
        assertEquals((flow.oidcService.baseUrl + "/oidc/authorize").toString(), jsonResponse.getString("authorization_endpoint"), "Correct authorization endpoint")
        assertEquals((flow.oidcService.baseUrl + "/oidc/jwks").toString(), jsonResponse.getString("jwks_uri"), "Correct jwks uri")
    }

    @Unroll
    @Feature("OIDC_ENDPOINTS")
    def "Verify authorization endpoint"() {
        expect:
        JsonPath jsonResponse = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        Response authorizationResponse = Requests.getRequest(jsonResponse.getString("authorization_endpoint"))
        assertEquals(302, authorizationResponse.statusCode(), "Correct HTTP status code is returned")
        String errorDescription = Utils.getParamValueFromResponseHeader(authorizationResponse, "error")
        assertEquals("invalid_client", errorDescription, "Correct value for authorization endpoint")
    }

    @Unroll
    @Feature("OIDC_ENDPOINTS")
    def "Verify token endpoint"() {
        expect:
        flow.setOpenIdServiceConfiguration(Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl))
        Response tokenResponse = Requests.getWebToken(flow, "123456")
        assertEquals(400, tokenResponse.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", tokenResponse.getContentType(), "Correct Content-Type is returned")
        assertEquals("invalid_grant", tokenResponse.body().jsonPath().get("error"), "Correct error message is returned")
    }

    @Unroll
    @Feature("OIDC_ENDPOINTS")
    def "Verify user info endpoint"() {
        expect:
        flow.setOpenIdServiceConfiguration(Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl))
        Response userInfoResponse = Steps.getUserInfoResponseWithHeaderParam(flow, REQUEST_TYPE_GET, "456789")
        assertEquals(401, userInfoResponse.statusCode(), "Correct HTTP status code is returned")
        Map<String, String> errorMap = OpenIdUtils.getErrorFromAuthorizationHeader(userInfoResponse)
        assertEquals("\"request_unauthorized\"", errorMap.get("Bearer error"), "Correct error text is returned")
        assertEquals("\"The request could not be authorized. Check that you provided valid credentials in the right format.\"", errorMap.get("error_description"), "Correct error description is returned")
    }

    @Unroll
    @Feature("OIDC_ENDPOINTS")
    def "Verify keystore endpoint"() {
        expect:
        JsonPath jsonResponse = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        Response response = Requests.getRequest(jsonResponse.getString("jwks_uri"))
        assertTrue(response.getBody().jsonPath().getString("keys.n").size() > 300, "Correct n size")
        assertTrue(response.getBody().jsonPath().getString("keys.e").size() > 3, "Correct e size")
    }

}
