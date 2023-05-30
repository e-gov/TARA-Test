package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.greaterThan
import static org.hamcrest.Matchers.startsWith

class OidcRedirectRequestSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Feature("OIDC_AUTHENTICATION_SUCCESSFUL")
    @Feature("OIDC_AUTHENTICATION_FINISHED")
    def "Verify redirection url parameters"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Response midAuthResponse = Steps.authenticateWithMid(flow,"60001017716", "69100366")

        when:
        Response response = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(303))
        assertThat("Code parameter exists", Utils.getParamValueFromResponseHeader(response, "code").size(), greaterThan(60))
        assertThat("Correct state parameter", Utils.getParamValueFromResponseHeader(response, "state"), is(flow.state))
    }

    @Feature("OIDC_AUTHENTICATION_FAILED")
    def "Verify redirection url with invalid scope"() {
        given:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "my_scope", "et")

        when:
        Response response = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(303))
        assertThat("Correct state parameter", Utils.getParamValueFromResponseHeader(response, "state"), is(flow.state))
        assertThat("Correct error", Utils.getParamValueFromResponseHeader(response, "error"), is(ERROR_SCOPE))
        assertThat("Correct error description", Utils.getParamValueFromResponseHeader(response, "error_description"), startsWith("The requested scope is invalid"))
    }

    @Feature("OIDC_AUTHENTICATION_FAILED")
    def "Verify redirection url with invalid state"() {
        given:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap.put("state", "ab")

        when:
        Response response = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(303))
        assertThat("Correct state parameter", Utils.getParamValueFromResponseHeader(response, "state"), is("ab"))
        assertThat("Correct error", Utils.getParamValueFromResponseHeader(response, "error"), is(ERROR_STATE))
        assertThat("Correct error description", Utils.getParamValueFromResponseHeader(response, "error_description"), startsWith("The state is missing"))
    }

    @Feature("OIDC_AUTHENTICATION_FAILED")
    def "Verify redirection url with unsupported response type"() {
        given:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap.put("response_type", "token")

        when:
        Response response = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(303))
        assertThat("Correct state parameter", Utils.getParamValueFromResponseHeader(response, "state"), is(flow.state))
        assertThat("Correct error", Utils.getParamValueFromResponseHeader(response, "error"), is("unsupported_response_type"))
        assertThat("Correct error description", Utils.getParamValueFromResponseHeader(response, "error_description"), startsWith("The authorization server does not support"))
    }

    @Feature("OIDC_AUTHENTICATION_FAILED")
    def "Verify redirection url with user cancel"() {
        given:
        Steps.startAuthenticationInTara(flow)
        Map paramsMap = ["error_code": REJECT_ERROR_CODE]
        Map cookieMap = ["SESSION": flow.sessionId]
        Response rejectResponse = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, cookieMap, paramsMap, [:])

        when:
        Response response = Steps.followRedirectWithCookies(flow, rejectResponse, flow.oidcService.cookies)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(303))
        assertThat("Correct state parameter", Utils.getParamValueFromResponseHeader(response, "state"), is(flow.state))
        assertThat("Correct error", Utils.getParamValueFromResponseHeader(response, "error"), is(REJECT_ERROR_CODE))
        assertThat("Correct error description", Utils.getParamValueFromResponseHeader(response, "error_description") , startsWith("User canceled the authentication process"))
    }

}
