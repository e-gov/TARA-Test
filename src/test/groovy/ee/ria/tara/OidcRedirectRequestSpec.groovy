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
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertTrue
import static org.junit.Assert.assertThat

@IgnoreIf({ properties['test.deployment.env'] == "idp" })
class OidcRedirectRequestSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Ignore()
    @Unroll
    @Feature("https://e-gov.github.io/TARA-Doku/TechnicalSpecification#42-redirect-request")
    def "Test the return request structure and coherence with TARA 1"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response midAuthResponse = Steps.authenticateWithMid(flow,"60001017716", "69100366")
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        // In addition to request structure validation, it is needed to verify the security elements, error cases...
        assertThat(authenticationFinishedResponse.getHeader("location"), equalTo("TARA1 generated request"))
    }

    @Unroll
    @Feature("OIDC_AUTHENTICATION_SUCCESSFUL")
    @Feature("OIDC_AUTHENTICATION_FINISHED")
    def "Verify redirection url parameters"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        Response midAuthResponse = Steps.authenticateWithMid(flow,"60001017716", "69100366")
        Response response = Steps.submitConsentAndFollowRedirects(flow, true, midAuthResponse)
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        assertTrue("Code parameter exists", Utils.getParamValueFromResponseHeader(response, "code").size() > 60)
        assertEquals("Correct state parameter", flow.state, Utils.getParamValueFromResponseHeader(response, "state"))
    }

    @Unroll
    @Feature("OIDC_AUTHENTICATION_FAILED")
    def "Verify redirection url with invalid scope"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "my_scope", "et")
        Response response = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)

        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        assertEquals("Correct state parameter", flow.state, Utils.getParamValueFromResponseHeader(response, "state"))
        assertEquals("Error parameter exists", "invalid_scope", Utils.getParamValueFromResponseHeader(response, "error"))
        assertThat("Error description parameter exists", Utils.getParamValueFromResponseHeader(response, "error_description") , Matchers.startsWith("The requested scope is invalid"))
    }

    @Unroll
    @Feature("OIDC_AUTHENTICATION_FAILED")
    def "Verify redirection url with invalid state"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap.put("state", "ab")
        Response response = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        assertEquals("Correct state parameter", "ab", Utils.getParamValueFromResponseHeader(response, "state"))
        assertEquals("Error parameter exists", "invalid_state", Utils.getParamValueFromResponseHeader(response, "error"))
        assertThat("Error description parameter exists", Utils.getParamValueFromResponseHeader(response, "error_description") , Matchers.startsWith("The state is missing"))
    }

    @Unroll
    @Feature("OIDC_AUTHENTICATION_FAILED")
    def "Verify redirection url with unsupported response type"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow)
        paramsMap.put("response_type", "token")
        Response response = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        assertEquals("Correct state parameter", flow.state, Utils.getParamValueFromResponseHeader(response, "state"))
        assertEquals("Error parameter exists", "unsupported_response_type", Utils.getParamValueFromResponseHeader(response, "error"))
        assertThat("Error description parameter exists", Utils.getParamValueFromResponseHeader(response, "error_description") , Matchers.startsWith("The authorization server does not support"))
    }

    @Unroll
    @Feature("OIDC_AUTHENTICATION_FAILED")
    def "Verify redirection url with user cancel"() {
        expect:
        Steps.startAuthenticationInTara(flow)
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "error_code", REJECT_ERROR_CODE)
        HashMap<String, String> cookieMap = (HashMap) Collections.emptyMap()
        def map3 = Utils.setParameter(cookieMap, "SESSION", flow.sessionId)
        Response rejectResponse = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullAuthRejectUrl, cookieMap, paramsMap, Collections.emptyMap())
        Response response = Steps.followRedirectWithCookies(flow, rejectResponse, flow.oidcService.cookies)
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        assertEquals("Correct state parameter", flow.state, Utils.getParamValueFromResponseHeader(response, "state"))
        assertEquals("Error parameter exists", "user_cancel", Utils.getParamValueFromResponseHeader(response, "error"))
        assertThat("Error description parameter exists", Utils.getParamValueFromResponseHeader(response, "error_description") , Matchers.startsWith("User canceled the authentication process"))
    }

}
