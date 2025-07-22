package ee.ria.tara

import ee.ria.tara.model.OidcError
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.http.Method
import io.restassured.path.json.JsonPath
import io.restassured.response.Response

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.allOf
import static org.hamcrest.Matchers.equalToIgnoringCase
import static org.hamcrest.Matchers.greaterThan
import static org.hamcrest.Matchers.hasItem
import static org.hamcrest.Matchers.hasSize
import static org.hamcrest.Matchers.is

class OidcMetadataSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Feature("OIDC_DISCOVERY_ENDPOINT")
    def "Verify discovery path #path"() {
        when:
        Response response = Requests.getRequest(flow, flow.oidcService.baseUrl + path)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        assertThat("Correct issuer", response.jsonPath().getString("issuer"), equalToIgnoringCase(flow.oidcService.baseUrl))

        where:
        path                                     | _
        "/.well-known/openid-configuration"      | _
        "/oidc/.well-known/openid-configuration" | _
    }

    @Feature("OIDC_DISCOVERY_CONTENT")
    def "Verify discovery content"() {
        when:
        JsonPath response = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)

        then:
        assertThat("Correct issuer", response.getString("issuer"), equalToIgnoringCase(flow.oidcService.baseUrl))
        List<String> scopesSupported = response.getList("scopes_supported")
        def scopeList = ["openid", "idcard", "mid", "smartid", "email", "phone", "eidas", "eidasonly"]
        scopeList.each {
            assertThat("Scope supported. Contains $it", scopesSupported.contains(it))
        }
        assertThat("Supported response types", response.getList("response_types_supported"), allOf(hasSize(1), hasItem("code")))
        assertThat("Supported subject types", response.getList("subject_types_supported"), allOf(hasSize(1), hasItem("public")))
        assertThat("Supported claim types", response.getList("claim_types_supported"), allOf(hasSize(1), hasItem("normal")))

        List<String> claimsSupported = response.getList("claims_supported")
        def claimsList = ["sub", "given_name", "family_name", "date_of_birth"]
        claimsList.add("represents_legal_person.name")
        claimsList.add("represents_legal_person.registry_code")
        claimsList.add("email")
        claimsList.add("email_verified")
        claimsList.add("phonenumber")
        claimsList.add("phonenumber_verified")
        claimsList.each {
            assertThat("Claim supported. Contains $it", claimsSupported.contains(it))
        }
        assertThat("Supported grant types", response.getList("grant_types_supported"), allOf(hasSize(1), hasItem("authorization_code")))
        assertThat("Supported alg values", response.getList("id_token_signing_alg_values_supported"), allOf(hasSize(1), hasItem("RS256")))
        List<String> localesSupported = response.getList("ui_locales_supported")
        def localesList = ["et", "en", "ru"]
        localesList.each {
            assertThat("Locale $it supported", localesSupported.contains(it))
        }
        assertThat("Correct token endpoint", response.getString("token_endpoint"), equalToIgnoringCase(flow.oidcService.baseUrl + "/oidc/token"))
        assertThat("Correct userinfo endpoint", response.getString("userinfo_endpoint"), equalToIgnoringCase(flow.oidcService.baseUrl + "/oidc/profile"))
        assertThat("Correct authorization endpoint", response.getString("authorization_endpoint"), equalToIgnoringCase(flow.oidcService.fullAuthorizationUrl))
        assertThat("Correct jwks uri", response.getString("jwks_uri"), equalToIgnoringCase(flow.oidcService.baseUrl + "/oidc/jwks"))
    }

    @Feature("OIDC_ENDPOINTS")
    def "Verify authorization endpoint"() {
        given:
        JsonPath jsonResponse = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)

        when:
        Response authorizationResponse = Requests.getRequest(flow, jsonResponse.getString('authorization_endpoint'))

        then:
        assertThat("Correct HTTP status code", authorizationResponse.statusCode, is(302))
        assertThat("Correct value for authorization endpoint", Utils.getParamValueFromResponseHeader(authorizationResponse, "error"), is(OidcError.INVALID_CLIENT.code))
    }

    @Feature("OIDC_ENDPOINTS")
    def "Verify token endpoint"() {
        given:
        flow.setOpenIdServiceConfiguration(Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl))

        when:
        Response tokenResponse = Requests.webTokenBasicRequest(flow, "123456")

        then:
        assertThat("Correct HTTP status code", tokenResponse.statusCode, is(400))
        assertThat("Correct Content-Type", tokenResponse.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", tokenResponse.jsonPath().getString("error"), is(OidcError.INVALID_GRANT.code))
    }

    @Feature("OIDC_ENDPOINTS")
    def "Verify user info endpoint"() {
        given:
        flow.setOpenIdServiceConfiguration(Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl))

        when:
        Response response = Steps.getUserInfoResponseWithHeaderParam(flow, Method.GET, "456789")

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(401))
        assertThat("Correct error text", response.jsonPath().getString("error"), is(OidcError.REQUEST_UNAUTHORIZED.code))
        assertThat("Correct error description", response.jsonPath().getString("error_description"), is("The request could not be authorized. Check that you provided valid credentials in the right format."))
    }

    @Feature("OIDC_ENDPOINTS")
    def "Verify keystore endpoint"() {
        given:
        JsonPath jsonResponse = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)

        when:
        Response response = Requests.getRequest(flow, jsonResponse.getString("jwks_uri"))

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        assertThat("Correct Content-Type", response.contentType, is("application/json; charset=utf-8"))
        assertThat("Correct n size", response.jsonPath().getString("keys.n").size(), greaterThan(300))
        assertThat("Correct e size", response.jsonPath().getString("keys.e").size(), greaterThan(3))
    }
}
