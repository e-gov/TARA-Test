package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.hamcrest.Matchers
import spock.lang.Ignore
import spock.lang.IgnoreIf
import spock.lang.Unroll

import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.startsWith
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat
import static org.junit.Assert.assertTrue

@IgnoreIf({ properties['test.deployment.env'] == "idp" })
class OidcUserInfoRequestSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Ignore()
    @Unroll
    @Feature("https://e-gov.github.io/TARA-Doku/TechnicalSpecification#44-user-info-request")
    def "Test all input parameters and verify the structure and element coherence compared to TARA1 on responses"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response midAuthResponse = Steps.authenticateWithMid(flow,"60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        Response userInfoResponse //= Steps.getUserInfoResponse(flow, authenticationFinishedResponse)
        // We need only to test that the input and output of the first request in most cases
        assertThat(userInfoResponse, equalTo("TARA1 response"))
    }

    @Unroll
    @Feature("OIDC_USERINFO_ENDPOINT")
    @Feature("OIDC_USERINFO_REQUEST_VALIDATION")
    @Feature("OIDC_USERINFO_RESPONSE_OK")
    @Feature("OIDC_USERINFO_CLAIMS")
    def "Verify user info response with query parameter"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        String idCode = "60001017716"
        String phoneNo = "69100366"
        Response midAuthResponse = Steps.authenticateWithMid(flow,idCode, phoneNo)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        String accessToken = tokenResponse.body().jsonPath().getString("access_token")
        Response userInfoResponse = Steps.getUserInfoResponseWithQueryParam(flow, REQUEST_TYPE_GET, accessToken)
        assertEquals("Correct HTTP status code is returned", 200, userInfoResponse.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json; charset=utf-8", userInfoResponse.getContentType())

        assertThat(userInfoResponse.getBody().jsonPath().getString("acr"),  equalTo("high"))
        assertThat(userInfoResponse.getBody().jsonPath().getList("amr")[0].toString(), equalTo("mID"))
        // TARA2-153
        // long authTime = userInfoResponse.getBody().jsonPath().getLong("auth_time")
        // LocalDateTime ldt = Instant.ofEpochSecond(authTime).atZone(ZoneId.systemDefault()).toLocalDateTime()
        // TODO compare auth_time
        assertThat(userInfoResponse.getBody().jsonPath().getString("sub"),  equalTo("EE" + idCode))
        // TODO remove profile_attributes level
        assertThat(userInfoResponse.getBody().jsonPath().getString("profile_attributes.date_of_birth"),  equalTo("2000-01-01"))
        assertThat(userInfoResponse.getBody().jsonPath().getString("profile_attributes.family_name"),  equalTo("TESTNUMBER"))
        assertThat(userInfoResponse.getBody().jsonPath().getString("profile_attributes.given_name"),  equalTo("ONE"))
    }
    @Ignore // TARA2-154
    @Unroll
    @Feature("OIDC_USERINFO_ENDPOINT")
    @Feature("OIDC_USERINFO_REQUEST_VALIDATION")
    @Feature("OIDC_USERINFO_RESPONSE_OK")
    @Feature("OIDC_USERINFO_CLAIMS")
    @Feature("OIDC_SCOPE_EMAIL")
    def "Verify user info response: auth id-card, email scope"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid email")
        Response idCardAuthResponse = Steps.authenticateWithIdCard(flow, "src/test/resources/joeorg-auth.pem")

        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, idCardAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        String accessToken = tokenResponse.body().jsonPath().getString("access_token")
        Response userInfoResponse = Steps.getUserInfoResponseWithHeaderParam(flow, REQUEST_TYPE_GET, accessToken)
        assertEquals("Correct HTTP status code is returned", 200, userInfoResponse.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json; charset=utf-8", userInfoResponse.getContentType())

        assertThat(userInfoResponse.getBody().jsonPath().getString("acr"),  equalTo("high"))
        assertThat(userInfoResponse.getBody().jsonPath().getList("amr")[0].toString(), equalTo("idcard"))
        assertThat(userInfoResponse.getBody().jsonPath().getString("sub"),  equalTo("EE38001085718"))
        // TODO remove profile_attributes level TARA2-153
        assertThat(userInfoResponse.getBody().jsonPath().getString("profile_attributes.date_of_birth"),  equalTo("1980-01-08"))
        assertThat(userInfoResponse.getBody().jsonPath().getString("profile_attributes.family_name"),  equalTo("JÕEORG"))
        assertThat(userInfoResponse.getBody().jsonPath().getString("profile_attributes.given_name"),  equalTo("JAAK-KRISTJAN"))
        assertThat(userInfoResponse.getBody().jsonPath().getString("profile_attributes.email"), equalTo("38001085718@eesti.ee"))
        assertEquals(false, userInfoResponse.getBody().jsonPath().getBoolean("profile_attributes.email_verified"))
    }

    @Ignore // TARA2-154
    @Unroll
    @Feature("OIDC_USERINFO_ENDPOINT")
    @Feature("OIDC_USERINFO_REQUEST_VALIDATION")
    @Feature("OIDC_USERINFO_RESPONSE_OK")
    @Feature("OIDC_USERINFO_CLAIMS")
    @Feature("OIDC_SCOPE_PHONE")
    def "Verify user info response: auth id-card, phone scope"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid email")
        Response idCardAuthResponse = Steps.authenticateWithIdCard(flow, "src/test/resources/joeorg-auth.pem")

        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, idCardAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        String accessToken = tokenResponse.body().jsonPath().getString("access_token")
        Response userInfoResponse = Steps.getUserInfoResponseWithHeaderParam(flow, REQUEST_TYPE_GET, accessToken)
        assertEquals("Correct HTTP status code is returned", 200, userInfoResponse.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json; charset=utf-8", userInfoResponse.getContentType())

        assertThat(userInfoResponse.getBody().jsonPath().getString("acr"),  equalTo("high"))
        assertThat(userInfoResponse.getBody().jsonPath().getList("amr")[0].toString(), equalTo("idcard"))
        assertThat(userInfoResponse.getBody().jsonPath().getString("sub"),  equalTo("EE38001085718"))
        // TODO remove profile_attributes level TARA2-153
        assertThat(userInfoResponse.getBody().jsonPath().getString("profile_attributes.date_of_birth"),  equalTo("1980-01-08"))
        assertThat(userInfoResponse.getBody().jsonPath().getString("profile_attributes.family_name"),  equalTo("JÕEORG"))
        assertThat(userInfoResponse.getBody().jsonPath().getString("profile_attributes.given_name"),  equalTo("JAAK-KRISTJAN"))
        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.phone_number") == null)
        // TARA2-154
        // assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.phone_number_verified") == null)
    }

    @Ignore //TARA2-154
    @Unroll
    @Feature("OIDC_USERINFO_ENDPOINT")
    @Feature("OIDC_USERINFO_REQUEST_VALIDATION")
    @Feature("OIDC_USERINFO_RESPONSE_OK")
    @Feature("OIDC_USERINFO_CLAIMS")
    def "Verify user info response: auth id-card, openid scope"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid")
        Response idCardAuthResponse = Steps.authenticateWithIdCard(flow, "src/test/resources/joeorg-auth.pem")

        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, idCardAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        String accessToken = tokenResponse.body().jsonPath().getString("access_token")
        Response userInfoResponse = Steps.getUserInfoResponseWithHeaderParam(flow, REQUEST_TYPE_GET, accessToken)
        assertEquals("Correct HTTP status code is returned", 200, userInfoResponse.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json; charset=utf-8", userInfoResponse.getContentType())

        assertThat(userInfoResponse.getBody().jsonPath().getString("acr"),  equalTo("high"))
        assertThat(userInfoResponse.getBody().jsonPath().getList("amr")[0].toString(), equalTo("idcard"))
        assertThat(userInfoResponse.getBody().jsonPath().getString("sub"),  equalTo("EE38001085718"))
        // TODO remove profile_attributes level TARA2-153
        assertThat(userInfoResponse.getBody().jsonPath().getString("profile_attributes.date_of_birth"),  equalTo("1980-01-08"))
        assertThat(userInfoResponse.getBody().jsonPath().getString("profile_attributes.family_name"),  equalTo("JÕEORG"))
        assertThat(userInfoResponse.getBody().jsonPath().getString("profile_attributes.given_name"),  equalTo("JAAK-KRISTJAN"))

        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.email") == null)
        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.email_verified") == null)
        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.phone_number") == null)
        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.phone_number_verified") == null)
    }

    @Ignore // TARA2-154
    @Unroll
    @Feature("OIDC_USERINFO_ENDPOINT")
    @Feature("OIDC_USERINFO_RESPONSE_OK")
    @Feature("OIDC_USERINFO_CLAIMS")
    @Feature("OIDC_SCOPE_PHONE")
    def "Verify user info response: auth mID, phone scope"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid phone")
        String idCode = "60001017716"
        String phoneNo = "69100366"
        Response midAuthResponse = Steps.authenticateWithMid(flow,idCode, phoneNo)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        String accessToken = tokenResponse.body().jsonPath().getString("access_token")
        Response userInfoResponse = Steps.getUserInfoResponseWithQueryParam(flow, REQUEST_TYPE_GET, accessToken)
        assertEquals("Correct HTTP status code is returned", 200, userInfoResponse.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json; charset=utf-8", userInfoResponse.getContentType())
        // TODO remove profile_attributes level TARA2-153
        assertThat(userInfoResponse.getBody().jsonPath().getString("profile_attributes.given_name"),  equalTo("ONE"))
        assertThat(userInfoResponse.getBody().jsonPath().getString("profile_attributes.phone_number"), Matchers.containsString(phoneNo))
        assertEquals(true, userInfoResponse.getBody().jsonPath().getBoolean("profile_attributes.phone_number_verified"))
        // TARA2-154 assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.email_verified") == null)
    }

    @Ignore // TARA2-154
    @Unroll
    @Feature("OIDC_USERINFO_ENDPOINT")
    @Feature("OIDC_USERINFO_RESPONSE_OK")
    @Feature("OIDC_USERINFO_CLAIMS")
    def "Verify user info response: auth mID, openid scope"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid")
        String idCode = "60001017716"
        String phoneNo = "69100366"
        Response midAuthResponse = Steps.authenticateWithMid(flow,idCode, phoneNo)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        String accessToken = tokenResponse.body().jsonPath().getString("access_token")
        Response userInfoResponse = Steps.getUserInfoResponseWithQueryParam(flow, REQUEST_TYPE_GET, accessToken)
        assertEquals("Correct HTTP status code is returned", 200, userInfoResponse.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json; charset=utf-8", userInfoResponse.getContentType())
        // TODO remove profile_attributes level TARA2-153
        assertThat(userInfoResponse.getBody().jsonPath().getString("profile_attributes.given_name"),  equalTo("ONE"))
        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.email") == null)
        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.email_verified") == null)
        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.phone_number") == null)
        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.phone_number_verified") == null)

    }

    @Ignore //TARA2-154
    @Unroll
    @Feature("OIDC_USERINFO_ENDPOINT")
    @Feature("OIDC_USERINFO_RESPONSE_OK")
    @Feature("OIDC_USERINFO_CLAIMS")
    def "Verify user info response: auth mID, email scope"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid email")
        String idCode = "60001017716"
        String phoneNo = "69100366"
        Response midAuthResponse = Steps.authenticateWithMid(flow,idCode, phoneNo)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        String accessToken = tokenResponse.body().jsonPath().getString("access_token")
        Response userInfoResponse = Steps.getUserInfoResponseWithQueryParam(flow, REQUEST_TYPE_GET, accessToken)
        assertEquals("Correct HTTP status code is returned", 200, userInfoResponse.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json; charset=utf-8", userInfoResponse.getContentType())
        // TODO remove profile_attributes level TARA2-153
        assertThat(userInfoResponse.getBody().jsonPath().getString("profile_attributes.given_name"),  equalTo("ONE"))
        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.email") == null)
        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.email_verified") == null)
    }

    @Ignore // TARA2-154
    @Unroll
    @Feature("OIDC_USERINFO_ENDPOINT")
    @Feature("OIDC_USERINFO_RESPONSE_OK")
    @Feature("OIDC_USERINFO_CLAIMS")
    @Feature("OIDC_SCOPE_EMAIL")
    def "Verify user info response: auth Smart-ID, email scope"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid email")
        Response sidAuthResponse = Steps.authenticateWithSid(flow,"10101010005")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, sidAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        String accessToken = tokenResponse.body().jsonPath().getString("access_token")
        Response userInfoResponse = Steps.getUserInfoResponseWithQueryParam(flow, REQUEST_TYPE_GET, accessToken)
        assertEquals("Correct HTTP status code is returned", 200, userInfoResponse.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json; charset=utf-8", userInfoResponse.getContentType())
        // TODO remove profile_attributes level TARA2-153
        assertThat(userInfoResponse.getBody().jsonPath().getString("profile_attributes.given_name"),  equalTo("DEMO"))
        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.email") == null)
        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.email_verified") == null)
        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.phone_number") == null)
        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.phone_number_verified") == null)
    }

    @Ignore //TARA2-154
    @Unroll
    @Feature("OIDC_USERINFO_ENDPOINT")
    @Feature("OIDC_USERINFO_RESPONSE_OK")
    @Feature("OIDC_USERINFO_CLAIMS")
    def "Verify user info response: auth Smart-ID, phone scope"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid phone") // smartid
        Response sidAuthResponse = Steps.authenticateWithSid(flow,"10101010005")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, sidAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        String accessToken = tokenResponse.body().jsonPath().getString("access_token")
        Response userInfoResponse = Steps.getUserInfoResponseWithQueryParam(flow, REQUEST_TYPE_GET, accessToken)
        assertEquals("Correct HTTP status code is returned", 200, userInfoResponse.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json; charset=utf-8", userInfoResponse.getContentType())
        // TODO remove profile_attributes level TARA2-153
        assertThat(userInfoResponse.getBody().jsonPath().getString("profile_attributes.given_name"),  equalTo("DEMO"))
        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.email") == null)
        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.email_verified") == null)
        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.phone_number") == null)
        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.phone_number_verified") == null)
    }

    @Unroll
    @Feature("OIDC_USERINFO_ENDPOINT")
    @Feature("OIDC_USERINFO_RESPONSE_OK")
    @Feature("OIDC_USERINFO_CLAIMS")
    def "Verify user info response: auth Smart-ID, openid scope"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid smartid") // smartid
        Response sidAuthResponse = Steps.authenticateWithSid(flow,"10101010005")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, sidAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        String accessToken = tokenResponse.body().jsonPath().getString("access_token")
        Response userInfoResponse = Steps.getUserInfoResponseWithQueryParam(flow, REQUEST_TYPE_GET, accessToken)
        assertEquals("Correct HTTP status code is returned", 200, userInfoResponse.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json; charset=utf-8", userInfoResponse.getContentType())
        // TODO remove profile_attributes level TARA2-153
        assertThat(userInfoResponse.getBody().jsonPath().getString("profile_attributes.given_name"),  equalTo("DEMO"))
        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.email") == null)
        assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.phone_number") == null)
        // TARA2-154
        // assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.email_verified") == null)
        // assertTrue(userInfoResponse.getBody().jsonPath().getString("profile_attributes.phone_number_verified") == null)
    }

    @Unroll
    @Feature("OIDC_USERINFO_RESPONSE_NOK")
    def "Unsupported request types in header #requestType"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid")
        Response idCardAuthResponse = Steps.authenticateWithIdCard(flow, "src/test/resources/joeorg-auth.pem")

        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, idCardAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        String accessToken = tokenResponse.body().jsonPath().getString("access_token")
        Response userInfoResponse = Steps.getUserInfoResponseWithHeaderParam(flow, requestType, accessToken)
        assertEquals("Correct HTTP status code is returned", statusCode, userInfoResponse.statusCode())

        where:
        requestType || statusCode
        // TARA2-153 "post" || 405
        "delete" || 405
        "patch" || 405
        "put" || 405
        // TARA2-153 "options" || 405
    }

    @Unroll
    @Feature("OIDC_USERINFO_RESPONSE_NOK")
    def "Invalid access token in header"() {
        expect:
        String accessToken = "access.Token.12345"
        Response response = Steps.getUserInfoResponseWithHeaderParam(flow, REQUEST_TYPE_GET, accessToken)
        assertEquals("Correct HTTP status code is returned", 401, response.statusCode())
        assertThat("Correct Content-Type is returned", response.getContentType(), Matchers.startsWith("application/json"))
        assertEquals("Correct error is returned", "request_unauthorized", response.body().jsonPath().get("error"))
        Map<String, String> errorMap = OpenIdUtils.getErrorFromAuthorizationHeader(response)
        assertEquals("Correct error text is returned","request_unauthorized", errorMap.get("error"))
        assertEquals("Correct error description is returned", "The request could not be authorized.", errorMap.get("error_description"))
        assertEquals("Correct error is returned", "Check that you provided valid credentials in the right format.", errorMap.get("error_hint"))

    }

    @Unroll
    @Feature("OIDC_USERINFO_RESPONSE_NOK")
    def "Invalid access token as parameter"() {
        expect:
        String accessToken = "access.Token.12345"
        Response response = Steps.getUserInfoResponseWithQueryParam(flow, REQUEST_TYPE_GET, accessToken)
        assertEquals("Correct HTTP status code is returned", 401, response.statusCode())
        assertThat("Correct Content-Type is returned", response.getContentType(), Matchers.startsWith("application/json"))
        assertEquals("Correct error is returned", "request_unauthorized", response.body().jsonPath().get("error"))
        Map<String, String> errorMap = OpenIdUtils.getErrorFromAuthorizationHeader(response)
        assertEquals("Correct error text is returned","request_unauthorized", errorMap.get("error"))
        assertThat("Correct error description is returned", errorMap.get("error_description"), startsWith("The request could not be authorized."))
        assertEquals("Correct error is returned", "Check that you provided valid credentials in the right format.", errorMap.get("error_hint"))
    }

    @Ignore
    @Unroll
    @Feature("OIDC_USERINFO_ACCESSTOKEN_MISSING")
    @Feature("OIDC_USERINFO_RESPONSE_NOK")
    def "Userinfo request without access token"() {
        expect:

        Response response = Requests.getRequestWithParams(flow
                , flow.openIdServiceConfiguration.getString("userinfo_endpoint")
                , Collections.emptyMap()
                , Collections.emptyMap())
        // TARA2-153
        // assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertThat("Correct Content-Type is returned", response.getContentType(), Matchers.startsWith("application/json"))
        assertEquals("Correct error is returned", "request_unauthorized", response.body().jsonPath().get("error"))
        assertThat("Correct error_description is returned", response.body().jsonPath().getString("error_description"), Matchers.endsWith("Check that you provided valid credentials in the right format."))

        Map<String, String> errorMap = OpenIdUtils.getErrorFromAuthorizationHeader(response)
    //    assertEquals("Correct error text is returned","invalid_request", errorMap.get("error"))
     //   assertEquals("Correct error description is returned", "The request could not be authorized", errorMap.get("error_description"))
    }

}
