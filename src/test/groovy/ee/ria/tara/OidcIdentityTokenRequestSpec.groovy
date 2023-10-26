package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.qameta.allure.restassured.AllureRestAssured
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static io.restassured.RestAssured.given
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.endsWith
import static org.hamcrest.Matchers.greaterThan
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.lessThan
import static org.hamcrest.Matchers.allOf
import static org.hamcrest.Matchers.startsWith

class OidcIdentityTokenRequestSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Feature("OIDC_ID_TOKEN")
    def "Verify ID token mandatory elements"() {
        given: "Start authentication"
        Steps.startAuthenticationInTara(flow)

        when: "Obtain claims from token"
        Response tokenResponse = Steps.authenticateWithWebEid(flow)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then: "Verify claims"
        assertThat("Jti claim exists", claims.getJWTID().size(), is(36))
        assertThat("Correct issuer claim", claims.issuer, is(flow.openIdServiceConfiguration.get("issuer")))
        assertThat("Correct audience", claims.audience[0], is(flow.oidcClientPublic.clientId))
        Date date = new Date()
        assertThat("Expected current: " + date + " to be after nbf: " + claims.notBeforeTime, date.after(claims.notBeforeTime), is(true))
        assertThat("Iat claim exists", Math.abs(date.time - claims.getDateClaim("iat").time), lessThan(10000L))
        assertThat("Correct subject claim", claims.subject, is("EE38001085718"))
        assertThat("Correct date of birth", claims.getJSONObjectClaim("profile_attributes")["date_of_birth"], is("1980-01-08"))
        assertThat("Correct given name", claims.getJSONObjectClaim("profile_attributes")["given_name"], is("JAAK-KRISTJAN"))
        assertThat("Correct family name", claims.getJSONObjectClaim("profile_attributes")["family_name"], is("JÕEORG"))
        assertThat("Correct amr value", claims.getStringArrayClaim("amr")[0].toString(), is("idcard"))
        assertThat("Correct state value", claims.getClaim("state"), is(flow.state))
        assertThat("Correct LoA level", claims.getClaim("acr"), is("high"))
        assertThat("At_hash claim exists", claims.getStringClaim("at_hash").size(), greaterThan(20))
    }

    @Feature("OIDC_ID_TOKEN")
    def "Verify ID token claims with optional elements by phone scope"() {
        given: "Start authentication"
        Steps.startAuthenticationInTara(flow, "openid phone")
        Response midAuthResponse = Steps.authenticateWithMid(flow, "60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)

        when: "Obtain claims from token"
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then: "Verify optional claims"
        assertThat("Correct scope value", tokenResponse.jsonPath().getString("scope"), is("openid phone"))
        assertThat("Correct subject claim", claims.subject, is("EE60001017716"))
        assertThat("Phone_number claim exists", claims.getStringClaim("phone_number"), is("+37269100366"))
        assertThat("Phone_number_verified claim exists", claims.getBooleanClaim("phone_number_verified"), is(true))
    }

    @Feature("OIDC_ID_TOKEN")
    def "Verify ID token claims with optional elements by email scope"() {
        given: "Start authentication"
        Steps.startAuthenticationInTara(flow, "openid email")

        when: "Obtain claims from token"
        Response tokenResponse = Steps.authenticateWithWebEid(flow)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then: "Verify optional claims"
        assertThat("Correct scope value", tokenResponse.jsonPath().getString("scope"), is("openid email"))
        assertThat("Correct subject claim", claims.getSubject(), is("EE38001085718"))
        assertThat("Phone_number claim exists", claims.getStringClaim("email"), is("jaak-kristjan.joeorg@eesti.ee"))
        assertThat("Phone_number_verified claim exists", claims.getBooleanClaim("email_verified"), is(false))
    }

    @Feature("OIDC_ID_TOKEN")
    def "Verify #clientJWTMethod token response with client_secret_basic configured client"() {
        given: "Start authentication"
        Steps.startAuthenticationInTaraWithClient(flow, flow.oidcClientPublic.clientId, flow.oidcClientPublic.clientSecret, flow.oidcClientPublic.fullResponseUrl)

        when: "Request token with #label client authentication method"
        Response tokenResponse = Steps.authenticateWithWebEid(flow, JWTBasic)

        then:
        if (JWTBasic) {
            assertThat("Correct HTTP status", tokenResponse.statusCode, is(200))
            assertThat("Correct token_type value", tokenResponse.jsonPath().getString("token_type"), is("bearer"))
            assertThat("Correct scope value", tokenResponse.jsonPath().getString("scope"), is("openid"))
            assertThat("Access_token element exists", tokenResponse.jsonPath().getString("access_token").size(), greaterThan(32))
            assertThat("Expires_in element exists", tokenResponse.jsonPath().getInt("expires_in"), greaterThan(60))
            assertThat("Id_token element exists", tokenResponse.jsonPath().getString("id_token").size(), greaterThan(1000))
        } else {
            assertThat("Correct HTTP status", tokenResponse.statusCode, is(401))
            assertThat("Correct error", tokenResponse.jsonPath().getString("error"), is(ERROR_CLIENT))
            assertThat("Correct error message", tokenResponse.jsonPath().getString("error_description"), containsString(
                    "The OAuth 2.0 Client supports client authentication method 'client_secret_basic', but method 'client_secret_post' was requested."))
        }

        where:
        clientJWTMethod      | JWTBasic | label
        "client_secret_basic" | true     | "correct"
        "client_secret_post" | false    | "incorrect"
    }

    @Feature("OIDC_ID_TOKEN")
    def "Verify #clientJWTMethod token response with client_secret_post configured client"() {
        given: "Start authentication"
        Steps.startAuthenticationInTaraWithClient(flow, flow.oidcClientPost.clientId, flow.oidcClientPrivate.clientSecret, flow.oidcClientPost.fullResponseUrl)

        when: "Request token with #label client authentication method"
        Response tokenResponse = Steps.authenticateWithWebEid(flow, JWTBasic)

        then:
        if (!JWTBasic) {
            assertThat("Correct HTTP status", tokenResponse.statusCode, is(200))
            assertThat("Correct token_type value", tokenResponse.jsonPath().getString("token_type"), is("bearer"))
            assertThat("Correct scope value", tokenResponse.jsonPath().getString("scope"), is("openid"))
            assertThat("Access_token element exists", tokenResponse.jsonPath().getString("access_token").size(), greaterThan(32))
            assertThat("Expires_in element exists", tokenResponse.jsonPath().getInt("expires_in"), greaterThan(60))
            assertThat("Id_token element exists", tokenResponse.jsonPath().getString("id_token").size(), greaterThan(1000))
        } else {
            assertThat("Correct HTTP status", tokenResponse.statusCode, is(401))
            assertThat("Correct error", tokenResponse.jsonPath().getString("error"), is(ERROR_CLIENT))
            assertThat("Correct error message", tokenResponse.jsonPath().getString("error_description"), containsString(
                    "The OAuth 2.0 Client supports client authentication method 'client_secret_post', but method 'client_secret_basic' was requested."))
        }

        where:
        clientJWTMethod       | JWTBasic | label
        "client_secret_basic" | true     | "incorrect"
        "client_secret_post"  | false    | "correct"
    }

    @Feature("OIDC_ID_TOKEN")
    def "Request ID token with client_secret_basic with incorrect request parameter #parameter should fail"() {
        given: "Start authentication"
        Steps.startAuthenticationInTara(flow)

        when: "Request token with incorrect #parameter"
        flow.("set" + parameter)("incorrect")
        Response tokenResponse = Steps.authenticateWithWebEid(flow)

        then:
        assertThat("Correct HTTP status", tokenResponse.statusCode, is(statusCode))
        assertThat("Correct error", tokenResponse.jsonPath().getString("error"), is(error))
        assertThat("Correct error message", tokenResponse.jsonPath().getString("error_description"), containsString(errorDescription))


        where:
        parameter      || statusCode | error                     | errorDescription
        "ClientId"     || 400        | ERROR_UNAUTHORIZED_CLIENT | "is not whitelisted"
        "ClientSecret" || 401        | ERROR_CLIENT              | "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)."
        "RedirectUri"  || 400        | ERROR_GRANT               | "The 'redirect_uri' from this request does not match the one from the authorize request."
    }

    @Feature("OIDC_ID_TOKEN")
    def "Request ID token with client_secret_post with incorrect request parameter: #parameter should fail"() {
        given: "Start authentication"
        Steps.startAuthenticationInTaraWithClient(flow, flow.oidcClientPost.clientId, flow.oidcClientPost.clientSecret, flow.oidcClientPost.fullResponseUrl)

        when: "Request token with incorrect #parameter"
        flow.("set" + parameter)("incorrect")
        Response tokenResponse = Steps.authenticateWithWebEid(flow, false)

        then:
        assertThat("Correct HTTP status", tokenResponse.statusCode, is(statusCode))
        assertThat("Correct error", tokenResponse.jsonPath().getString("error"), is(error))
        assertThat("Correct error message", tokenResponse.jsonPath().getString("error_description"), containsString(errorDescription))


        where:
        parameter      || statusCode | error                     | errorDescription
        "ClientId"     || 400        | ERROR_UNAUTHORIZED_CLIENT | "is not whitelisted"
        "ClientSecret" || 401        | ERROR_CLIENT              | "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)."
        "RedirectUri"  || 400        | ERROR_GRANT               | "The 'redirect_uri' from this request does not match the one from the authorize request."
    }


    @Feature("OPENID_CONNECT")
    def "Request an ID token twice with same authorization code with client_secret_basic should fail"() {
        given: "Obtain ID token"
        Steps.startAuthenticationInTara(flow)
        Response tokenResponse = Steps.authenticateWithWebEid(flow)

        when: "Request ID token again with the same authorization code"
        Response tokenResponse2 = Requests.webTokenBasicRequest(flow, flow.code)

        then:
        assertThat("Correct HTTP status code", tokenResponse.statusCode, is(200))
        assertThat("Correct HTTP status code", tokenResponse2.statusCode, is(400))
        assertThat("Correct Content-Type", tokenResponse2.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", tokenResponse2.jsonPath().getString("error"), is(ERROR_GRANT))
        assertThat("Correct error description", tokenResponse2.jsonPath().getString("error_description"), endsWith("The authorization code has already been used."))
    }

    @Feature("OPENID_CONNECT")
    def "Request an ID token twice with same authorization code with client_secret_post should fail"() {
        given: "Obtain ID token"
        Steps.startAuthenticationInTaraWithClient(flow, flow.oidcClientPost.clientId, flow.oidcClientPost.clientSecret, flow.oidcClientPost.fullResponseUrl)
        Response tokenResponse = Steps.authenticateWithWebEid(flow, false)

        when: "Request ID token again with the same authorization code"
        Response tokenResponse2 = Requests.webTokenPostRequest(flow, flow.code)

        then:
        assertThat("Correct HTTP status code", tokenResponse.statusCode, is(200))
        assertThat("Correct HTTP status code", tokenResponse2.statusCode, is(400))
        assertThat("Correct Content-Type", tokenResponse2.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", tokenResponse2.jsonPath().getString("error"), is(ERROR_GRANT))
        assertThat("Correct error description", tokenResponse2.jsonPath().getString("error_description"), endsWith("The authorization code has already been used."))
    }

    @Feature("OPENID_CONNECT")
    @Feature("OIDC_ID_TOKEN")
    def "Request token from a non-whitelisted address should fail"() {
        given: "Authenticate in TARA"
        Steps.startAuthenticationInTara(flow)
        Response midAuthResponse = Steps.authenticateWithMid(flow, "60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        String authorizationCode = Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "code")

        when: "Request token"
        Response tokenResponse = given()
                .filter(new AllureRestAssured())
                .params([grant_type  : "authorization_code",
                         code        : authorizationCode,
                         redirect_uri: flow.redirectUri])
                .auth().preemptive().basic("tara-client", "secret")
                .relaxedHTTPSValidation()
                .post(flow.openIdServiceConfiguration.getString("token_endpoint"))

        then:
        assertThat("Correct HTTP status code", tokenResponse.statusCode, is(400))
        assertThat("Correct error", tokenResponse.jsonPath().getString("error"), is(ERROR_UNAUTHORIZED_CLIENT))
        assertThat("Correct error description", tokenResponse.jsonPath().getString("error_description"),
                allOf(startsWith("Your IP address"), endsWith("is not whitelisted")))
    }

    @Feature("OPENID_CONNECT")
    @Feature("OIDC_ID_TOKEN")
    def "Request token with not allowed HTTP method: #method should fail"() {
        given: "Authenticate in TARA"
        Steps.startAuthenticationInTara(flow)
        Response midAuthResponse = Steps.authenticateWithMid(flow, "60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        String authorizationCode = Utils.getParamValueFromResponseHeader(authenticationFinishedResponse, "code")

        when: "Request token with incorrect HTTP method: #method"
        Response tokenResponse = given()
                .filter(new AllureRestAssured())
                .params([grant_type  : "authorization_code",
                         code        : authorizationCode,
                         redirect_uri: flow.redirectUri])
                .auth().preemptive().basic(flow.clientId, flow.clientSecret)
                .urlEncodingEnabled(true)
                .relaxedHTTPSValidation()
                .request(method, flow.openIdServiceConfiguration.getString("token_endpoint"))

        then:
        assertThat("Correct HTTP status code", tokenResponse.statusCode, is(405))
        assertThat("Correct message", tokenResponse.body.asString(), containsString("Method Not Allowed"))

        where:
        method   | _
        "get"    | _
        "put"    | _
        "patch"  | _
        "delete" | _
    }
}
