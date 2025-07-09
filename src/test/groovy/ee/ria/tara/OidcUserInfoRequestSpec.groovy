package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.hamcrest.Matchers.is
import static org.hamcrest.MatcherAssert.assertThat

class OidcUserInfoRequestSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Feature("OIDC_USERINFO_ENDPOINT")
    @Feature("OIDC_USERINFO_REQUEST_VALIDATION")
    @Feature("OIDC_USERINFO_RESPONSE_OK")
    @Feature("OIDC_USERINFO_CLAIMS")
    def "Verify user info response with query parameter"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Response midAuthResponse = Steps.authenticateWithMid(flow, "60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        String accessToken = tokenResponse.jsonPath().getString("access_token")

        when:
        Response userInfoResponse = Steps.getUserInfoResponseWithQueryParam(flow, REQUEST_TYPE_GET, accessToken)

        then:
        assertThat("Correct HTTP status code", userInfoResponse.statusCode, is(200))
        assertThat("Correct Content-Type", userInfoResponse.contentType, is("application/json; charset=utf-8"))
        assertThat("Correct acr", userInfoResponse.jsonPath().getString("acr"), is("high"))
        assertThat("Correct amr", userInfoResponse.jsonPath().getList("amr")[0].toString(), is("mID"))
        Date date = new Date()
        long authTime = userInfoResponse.jsonPath().getLong("auth_time")
        // 10 seconds
        assertThat("Correct auth_time", Math.abs(date.getTime() / 1000 - authTime) < 10L)
        assertThat("Correct subject", userInfoResponse.jsonPath().getString("sub"), is("EE60001017716"))
        assertThat("Correct date of birth", userInfoResponse.jsonPath().getString("date_of_birth"), is("2000-01-01"))
        assertThat("Correct family name", userInfoResponse.jsonPath().getString("family_name"), is("TESTNUMBER"))
        assertThat("Correct given name", userInfoResponse.jsonPath().getString("given_name"), is("ONE"))
    }

    @Feature("OIDC_USERINFO_ENDPOINT")
    @Feature("OIDC_USERINFO_REQUEST_VALIDATION")
    @Feature("OIDC_USERINFO_RESPONSE_OK")
    @Feature("OIDC_USERINFO_CLAIMS")
    @Feature("OIDC_SCOPE_EMAIL")
    def "Verify user info response: auth id-card, email scope"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid email")
        Response idCardAuthResponse = Steps.authenticateWithWebEid(flow)
        String accessToken = idCardAuthResponse.jsonPath().getString("access_token")

        when:
        Response userInfoResponse = Steps.getUserInfoResponseWithHeaderParam(flow, REQUEST_TYPE_GET, accessToken)

        then:
        assertThat("Correct HTTP status code", userInfoResponse.statusCode, is(200))
        assertThat("Correct Content-Type", userInfoResponse.contentType, is("application/json; charset=utf-8"))
        assertThat("Correct acr", userInfoResponse.jsonPath().getString("acr"), is("high"))
        assertThat("Correct amr", userInfoResponse.jsonPath().getList("amr")[0].toString(), is("idcard"))
        assertThat("Correct subject", userInfoResponse.jsonPath().getString("sub"), is("EE38001085718"))
        assertThat("Correct date of birth", userInfoResponse.jsonPath().getString("date_of_birth"), is("1980-01-08"))
        assertThat("Correct family name", userInfoResponse.jsonPath().getString("family_name"), is("JÕEORG"))
        assertThat("Correct given name", userInfoResponse.jsonPath().getString("given_name"), is("JAAK-KRISTJAN"))
        assertThat("Correct email", userInfoResponse.jsonPath().getString("email"), is("jaak-kristjan.joeorg@eesti.ee"))
        assertThat("Email verified false", userInfoResponse.jsonPath().getBoolean("email_verified"), is(false))
    }

    @Feature("OIDC_USERINFO_ENDPOINT")
    @Feature("OIDC_USERINFO_REQUEST_VALIDATION")
    @Feature("OIDC_USERINFO_RESPONSE_OK")
    @Feature("OIDC_USERINFO_CLAIMS")
    @Feature("OIDC_SCOPE_PHONE")
    def "Verify user info response: auth id-card, phone scope"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid email")
        Response idCardAuthResponse = Steps.authenticateWithWebEid(flow)
        String accessToken = idCardAuthResponse.jsonPath().getString("access_token")

        when:
        Response userInfoResponse = Steps.getUserInfoResponseWithHeaderParam(flow, REQUEST_TYPE_POST, accessToken)

        then:
        assertThat("Correct HTTP status code", userInfoResponse.statusCode, is(200))
        assertThat("Correct Content-Type", userInfoResponse.contentType, is("application/json; charset=utf-8"))
        assertThat("Correct acr", userInfoResponse.jsonPath().getString("acr"), is("high"))
        assertThat("Correct amr", userInfoResponse.jsonPath().getList("amr")[0].toString(), is("idcard"))
        assertThat("Correct subject", userInfoResponse.jsonPath().getString("sub"), is("EE38001085718"))
        assertThat("Correct date of birth", userInfoResponse.jsonPath().getString("date_of_birth"), is("1980-01-08"))
        assertThat("Correct family name", userInfoResponse.jsonPath().getString("family_name"), is("JÕEORG"))
        assertThat("Correct given name", userInfoResponse.jsonPath().getString("given_name"), is("JAAK-KRISTJAN"))
        assertThat("No phone number", userInfoResponse.jsonPath().getString("phone_number"), is(null))
        assertThat("No phone_number_verified", userInfoResponse.jsonPath().getString("phone_number_verified"), is(null))
    }

    @Feature("OIDC_USERINFO_ENDPOINT")
    @Feature("OIDC_USERINFO_REQUEST_VALIDATION")
    @Feature("OIDC_USERINFO_RESPONSE_OK")
    @Feature("OIDC_USERINFO_CLAIMS")
    def "Verify user info response: auth id-card, openid scope"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid")
        Response idCardAuthResponse = Steps.authenticateWithWebEid(flow)
        String accessToken = idCardAuthResponse.jsonPath().getString("access_token")

        when:
        Response userInfoResponse = Steps.getUserInfoResponseWithHeaderParam(flow, REQUEST_TYPE_GET, accessToken)

        then:
        assertThat("Correct HTTP status code", userInfoResponse.statusCode, is(200))
        assertThat("Correct Content-Type", userInfoResponse.contentType, is("application/json; charset=utf-8"))
        assertThat("Correct acr", userInfoResponse.jsonPath().getString("acr"), is("high"))
        assertThat("Correct amr", userInfoResponse.jsonPath().getList("amr")[0].toString(), is("idcard"))
        assertThat("Correct subject", userInfoResponse.jsonPath().getString("sub"), is("EE38001085718"))
        assertThat("Correct date of birth", userInfoResponse.jsonPath().getString("date_of_birth"), is("1980-01-08"))
        assertThat("Correct family name", userInfoResponse.jsonPath().getString("family_name"), is("JÕEORG"))
        assertThat("Correct given name", userInfoResponse.jsonPath().getString("given_name"), is("JAAK-KRISTJAN"))
        assertThat("No email", userInfoResponse.jsonPath().getString("email"), is(null))
        assertThat("No email_verified", userInfoResponse.jsonPath().getString("email_verified"), is(null))
        assertThat("No phone number", userInfoResponse.jsonPath().getString("phone_number"), is(null))
        assertThat("No phone_number_verified", userInfoResponse.jsonPath().getString("phone_number_verified"), is(null))
    }

    @Feature("OIDC_USERINFO_ENDPOINT")
    @Feature("OIDC_USERINFO_RESPONSE_OK")
    @Feature("OIDC_USERINFO_CLAIMS")
    @Feature("OIDC_SCOPE_PHONE")
    def "Verify user info response: auth mID, phone scope"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid phone")
        Response midAuthResponse = Steps.authenticateWithMid(flow, "60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        String accessToken = tokenResponse.jsonPath().getString("access_token")

        when:
        Response userInfoResponse = Steps.getUserInfoResponseWithQueryParam(flow, REQUEST_TYPE_POST, accessToken)

        then:
        assertThat("Correct HTTP status code", userInfoResponse.statusCode, is(200))
        assertThat("Correct Content-Type", userInfoResponse.contentType, is("application/json; charset=utf-8"))
        assertThat("Correct given name", userInfoResponse.jsonPath().getString("given_name"), is("ONE"))
        assertThat("Correct subject", userInfoResponse.jsonPath().getString("sub"), is("EE60001017716"))
        assertThat("Correct date of birth", userInfoResponse.jsonPath().getString("date_of_birth"), is("2000-01-01"))
        assertThat("Correct family name", userInfoResponse.jsonPath().getString("family_name"), is("TESTNUMBER"))
        assertThat("Correct phone number", userInfoResponse.jsonPath().getString("phone_number"), is("+37269100366"))
        assertThat("Phone number is verified", userInfoResponse.jsonPath().getBoolean("phone_number_verified"), is(true))
        assertThat("No email_verified", userInfoResponse.jsonPath().getString("email_verified"), is(null))
    }

    @Feature("OIDC_USERINFO_ENDPOINT")
    @Feature("OIDC_USERINFO_RESPONSE_OK")
    @Feature("OIDC_USERINFO_CLAIMS")
    def "Verify user info response: auth mID, openid scope"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid")
        Response midAuthResponse = Steps.authenticateWithMid(flow, "60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        String accessToken = tokenResponse.jsonPath().getString("access_token")

        when:
        Response userInfoResponse = Steps.getUserInfoResponseWithQueryParam(flow, REQUEST_TYPE_GET, accessToken)

        then:
        assertThat("Correct HTTP status code", userInfoResponse.statusCode, is(200))
        assertThat("Correct Content-Type", userInfoResponse.contentType, is("application/json; charset=utf-8"))
        assertThat("Correct given name", userInfoResponse.jsonPath().getString("given_name"), is("ONE"))
        assertThat("Correct subject", userInfoResponse.jsonPath().getString("sub"), is("EE60001017716"))
        assertThat("Correct date of birth", userInfoResponse.jsonPath().getString("date_of_birth"), is("2000-01-01"))
        assertThat("Correct family name", userInfoResponse.jsonPath().getString("family_name"), is("TESTNUMBER"))
        assertThat("No email", userInfoResponse.jsonPath().getString("email"), is(null))
        assertThat("No email_verified", userInfoResponse.jsonPath().getString("email_verified"), is(null))
        assertThat("No phone number", userInfoResponse.jsonPath().getString("phone_number"), is(null))
        assertThat("No phone_number_verified", userInfoResponse.jsonPath().getString("phone_number_verified"), is(null))

    }

    @Feature("OIDC_USERINFO_ENDPOINT")
    @Feature("OIDC_USERINFO_RESPONSE_OK")
    @Feature("OIDC_USERINFO_CLAIMS")
    def "Verify user info response: auth mID, email scope"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid email")
        Response midAuthResponse = Steps.authenticateWithMid(flow, "60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        String accessToken = tokenResponse.jsonPath().getString("access_token")

        when:
        Response userInfoResponse = Steps.getUserInfoResponseWithQueryParam(flow, REQUEST_TYPE_GET, accessToken)

        then:
        assertThat("Correct HTTP status code", userInfoResponse.statusCode, is(200))
        assertThat("Correct Content-Type", userInfoResponse.contentType, is("application/json; charset=utf-8"))
        assertThat("Correct given name", userInfoResponse.jsonPath().getString("given_name"), is("ONE"))
        assertThat("Correct subject", userInfoResponse.jsonPath().getString("sub"), is("EE60001017716"))
        assertThat("Correct date of birth", userInfoResponse.jsonPath().getString("date_of_birth"), is("2000-01-01"))
        assertThat("Correct family name", userInfoResponse.jsonPath().getString("family_name"), is("TESTNUMBER"))
        assertThat("No email", userInfoResponse.jsonPath().getString("email"), is(null))
        assertThat("No email_verified", userInfoResponse.jsonPath().getString("email_verified"), is(null))
    }

    @Feature("OIDC_USERINFO_ENDPOINT")
    @Feature("OIDC_USERINFO_RESPONSE_OK")
    @Feature("OIDC_USERINFO_CLAIMS")
    @Feature("OIDC_SCOPE_EMAIL")
    def "Verify user info response: auth Smart-ID, email scope"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid email")
        Response sidAuthResponse = Steps.authenticateWithSid(flow, "40404049996")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, sidAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        String accessToken = tokenResponse.jsonPath().getString("access_token")

        when:
        Response userInfoResponse = Steps.getUserInfoResponseWithQueryParam(flow, REQUEST_TYPE_GET, accessToken)

        then:
        assertThat("Correct HTTP status code", userInfoResponse.statusCode, is(200))
        assertThat("Correct Content-Type", userInfoResponse.contentType, is("application/json; charset=utf-8"))
        assertThat("Correct amr", userInfoResponse.jsonPath().getList("amr")[0].toString(), is("smartid"))
        assertThat("Correct given name", userInfoResponse.jsonPath().getString("given_name"), is("OK"))
        assertThat("Correct subject", userInfoResponse.jsonPath().getString("sub"), is("EE40404049996"))
        assertThat("Correct date of birth", userInfoResponse.jsonPath().getString("date_of_birth"), is("1904-04-04"))
        assertThat("Correct family name", userInfoResponse.jsonPath().getString("family_name"), is("TESTNUMBER"))
        assertThat("No email", userInfoResponse.jsonPath().getString("email"), is(null))
        assertThat("No email_verified", userInfoResponse.jsonPath().getString("email_verified"), is(null))
        assertThat("No phone number", userInfoResponse.jsonPath().getString("phone_number"), is(null))
        assertThat("No phone_number_verified", userInfoResponse.jsonPath().getString("phone_number_verified"), is(null))
    }

    @Feature("OIDC_USERINFO_ENDPOINT")
    @Feature("OIDC_USERINFO_RESPONSE_OK")
    @Feature("OIDC_USERINFO_CLAIMS")
    def "Verify user info response: auth Smart-ID, phone scope"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid phone")
        Response sidAuthResponse = Steps.authenticateWithSid(flow, "40404049996")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, sidAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        String accessToken = tokenResponse.jsonPath().getString("access_token")

        when:
        Response userInfoResponse = Steps.getUserInfoResponseWithQueryParam(flow, REQUEST_TYPE_GET, accessToken)

        then:
        assertThat("Correct HTTP status code", userInfoResponse.statusCode, is(200))
        assertThat("Correct Content-Type", userInfoResponse.contentType, is("application/json; charset=utf-8"))
        assertThat("Correct given name", userInfoResponse.jsonPath().getString("given_name"), is("OK"))
        assertThat("Correct subject", userInfoResponse.jsonPath().getString("sub"), is("EE40404049996"))
        assertThat("Correct date of birth", userInfoResponse.jsonPath().getString("date_of_birth"), is("1904-04-04"))
        assertThat("Correct family name", userInfoResponse.jsonPath().getString("family_name"), is("TESTNUMBER"))
        assertThat("No email", userInfoResponse.jsonPath().getString("email"), is(null))
        assertThat("No email_verified", userInfoResponse.jsonPath().getString("email_verified"), is(null))
        assertThat("No phone number", userInfoResponse.jsonPath().getString("phone_number"), is(null))
        assertThat("No phone_number_verified", userInfoResponse.jsonPath().getString("phone_number_verified"), is(null))
    }

    @Feature("OIDC_USERINFO_ENDPOINT")
    @Feature("OIDC_USERINFO_RESPONSE_OK")
    @Feature("OIDC_USERINFO_CLAIMS")
    def "Verify user info response: auth Smart-ID, openid scope"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid")
        Response sidAuthResponse = Steps.authenticateWithSid(flow, "40404049996")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, sidAuthResponse)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)
        String accessToken = tokenResponse.jsonPath().getString("access_token")

        when:
        Response userInfoResponse = Steps.getUserInfoResponseWithQueryParam(flow, REQUEST_TYPE_GET, accessToken)

        then:
        assertThat("Correct HTTP status code", userInfoResponse.statusCode, is(200))
        assertThat("Correct Content-Type", userInfoResponse.contentType, is("application/json; charset=utf-8"))
        assertThat("Correct given name", userInfoResponse.jsonPath().getString("given_name"), is("OK"))
        assertThat("Correct subject", userInfoResponse.jsonPath().getString("sub"), is("EE40404049996"))
        assertThat("Correct date of birth", userInfoResponse.jsonPath().getString("date_of_birth"), is("1904-04-04"))
        assertThat("Correct family name", userInfoResponse.jsonPath().getString("family_name"), is("TESTNUMBER"))
        assertThat("No email", userInfoResponse.jsonPath().getString("email"), is(null))
        assertThat("No phone number", userInfoResponse.jsonPath().getString("phone_number"), is(null))
        assertThat("No email_verified", userInfoResponse.jsonPath().getString("email_verified"), is(null))
        assertThat("No phone_number_verified", userInfoResponse.jsonPath().getString("phone_number_verified"), is(null))
    }

    @Feature("OIDC_USERINFO_RESPONSE_NOK")
    def "Unsupported request types in header #requestType"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid")
        Response idCardAuthResponse = Steps.authenticateWithWebEid(flow)
        String accessToken = idCardAuthResponse.jsonPath().getString("access_token")

        when:
        Response userInfoResponse = Steps.getUserInfoResponseWithHeaderParam(flow, requestType, accessToken)

        then:
        assertThat("Correct HTTP status code", userInfoResponse.statusCode, is(405))

        where:
        requestType | _
        // TARA2-153 "post" || 405
        "delete"    | _
        "patch"     | _
        "put"       | _
    }

    @Feature("OIDC_USERINFO_RESPONSE_NOK")
    def "Invalid access token in header"() {
        given:
        String accessToken = "access.Token.12345"

        when:
        Response response = Steps.getUserInfoResponseWithHeaderParam(flow, REQUEST_TYPE_GET, accessToken)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(401))
        assertThat("Correct Content-Type", response.contentType, is("application/json"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_UNAUTHORIZED))
        assertThat("Correct error description", response.jsonPath().getString("error_description"), is("The request could not be authorized. Check that you provided valid credentials in the right format."))
    }

    @Feature("OIDC_USERINFO_RESPONSE_NOK")
    def "Invalid access token as parameter"() {
        given:
        String accessToken = "access.Token.12345"

        when:
        Response response = Steps.getUserInfoResponseWithQueryParam(flow, REQUEST_TYPE_GET, accessToken)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(401))
        assertThat("Correct Content-Type", response.contentType, is("application/json"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_UNAUTHORIZED))
        assertThat("Correct error description", response.jsonPath().getString("error_description"), is("The request could not be authorized. Check that you provided valid credentials in the right format."))
    }

    @Feature("OIDC_USERINFO_ACCESSTOKEN_MISSING")
    @Feature("OIDC_USERINFO_RESPONSE_NOK")
    def "Userinfo request without access token"() {
        when:
        Response response = Requests.getRequest(flow, flow.openIdServiceConfiguration.getString("userinfo_endpoint"))

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(401))
        assertThat("Correct Content-Type", response.contentType, is("application/json"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_UNAUTHORIZED))
        assertThat("Correct error description", response.jsonPath().getString("error_description"), is("The request could not be authorized. Check that you provided valid credentials in the right format."))
    }

}
