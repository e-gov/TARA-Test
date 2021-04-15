package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.path.json.JsonPath
import io.restassured.response.Response
import spock.lang.IgnoreIf
import spock.lang.Unroll

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertTrue

@IgnoreIf({ properties['test.deployment.env'] == "idp" })
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
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())
        assertEquals("Correct issuer", (flow.oidcService.baseUrl.toString() + "/"), response.getBody().jsonPath().get("issuer"))

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
        assertEquals("Correct issuer", (flow.oidcService.baseUrl.toString() + "/"), jsonResponse.get("issuer"))
        List<String> scopesSupported = jsonResponse.getList("scopes_supported")
        def scopeList = ["openid", "idcard", "mid", "smartid", "email", "phone"] //, "eidas", "eidasonly"]
        scopeList.each {
            assertTrue("Scope supported. Contains $it", scopesSupported.contains(it))
        }

        assertEquals("Supported response types", "code", jsonResponse.getList("response_types_supported")[0])
        assertEquals("Supported subject types", "public", jsonResponse.getList("subject_types_supported")[0])
        assertEquals("Supported claim types", "normal", jsonResponse.getList("claim_types_supported")[0])

        List<String> claimsSupported = jsonResponse.getList("claims_supported")
        def claimsList = ["sub", "given_name", "family_name", "date_of_birth"]
        claimsList.add("represents_legal_person.name")
        claimsList.add("represents_legal_person.registry_code")
        claimsList.add("email")
        claimsList.add("email_verified")
        claimsList.add("phonenumber")
        claimsList.add("phonenumber_verified")
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
        // TARA2-151 , TARA2-219
        assertEquals("Correct token endpoint", (flow.oidcService.baseUrl + "/oidc/token").toString(), jsonResponse.getString("token_endpoint"))
        assertEquals("Correct userinfo endpoint", (flow.oidcService.baseUrl + "/oidc/profile").toString(), jsonResponse.getString("userinfo_endpoint"))
        assertEquals("Correct authorization endpoint", (flow.oidcService.baseUrl + "/oidc/authorize").toString(), jsonResponse.getString("authorization_endpoint"))
        assertEquals("Correct jwks uri", (flow.oidcService.baseUrl + "/oidc/jwks").toString(), jsonResponse.getString("jwks_uri"))
    }

    @Unroll
    @Feature("OIDC_ENDPOINTS")
    def "Verify authorization endpoint"() {
        expect:
        JsonPath jsonResponse = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        Response authorizationResponse = Requests.getRequest(jsonResponse.getString("authorization_endpoint"))
        assertEquals("Correct HTTP status code is returned", 302, authorizationResponse.statusCode())
        String errorDescription = Utils.getParamValueFromResponseHeader(authorizationResponse, "error")
        assertEquals("Correct value for authorization endpoint", "invalid_client", errorDescription)
    }

    @Unroll
    @Feature("OIDC_ENDPOINTS")
    def "Verify token endpoint"() {
        expect:
        flow.setOpenIdServiceConfiguration(Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl))
        Response tokenResponse = Requests.getWebToken(flow, "123456")
        assertEquals("Correct HTTP status code is returned", 400, tokenResponse.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", tokenResponse.getContentType())
        assertEquals("Correct error message is returned", "invalid_grant", tokenResponse.body().jsonPath().get("error"))
    }

    @Unroll
    @Feature("OIDC_ENDPOINTS")
    def "Verify user info endpoint"() {
        expect:
        flow.setOpenIdServiceConfiguration(Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl))
        Response userInfoResponse = Steps.getUserInfoResponseWithHeaderParam(flow, REQUEST_TYPE_GET, "456789")
        assertEquals("Correct HTTP status code is returned", 401, userInfoResponse.statusCode())
        Map<String, String> errorMap = OpenIdUtils.getErrorFromAuthorizationHeader(userInfoResponse)
        assertEquals("Correct error text is returned","request_unauthorized", errorMap.get("error"))
        assertEquals("Correct error description is returned", "The request could not be authorized.", errorMap.get("error_description"))
    }

    @Unroll
    @Feature("OIDC_ENDPOINTS")
    def "Verify keystore endpoint"() {
        expect:
        JsonPath jsonResponse = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        Response response = Requests.getRequest(jsonResponse.getString("jwks_uri"))
        assertTrue("Correct n size", response.getBody().jsonPath().getString("keys.n").size() > 300)
        assertTrue("Correct e size", response.getBody().jsonPath().getString("keys.e").size() > 3)
    }

}
