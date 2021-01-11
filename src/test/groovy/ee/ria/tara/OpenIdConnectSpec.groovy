package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.RandomStringUtils
import spock.lang.Ignore;
import spock.lang.Unroll
import com.nimbusds.jose.jwk.JWKSet

import java.nio.charset.StandardCharsets
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.startsWith
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat

class OpenIdConnectSpec extends TaraSpecification {
    Flow flow = new Flow(props)
    String RESPONSE_TYPE = "code"
    String UI_LOCALE_ET = "et"
    String DEFAULT_SCOPE = "openid"
    String MOCK_URI = "https://oidc-client-mock:8451/oauth/response"

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Unroll
    @Feature("OPENID_CONNECT")
    def "Metadata and token key ID matches"() {
        expect:
        Response oidcServiceResponse = Steps.authWithMobileID(flow)
        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        assertEquals("Correct HTTP status code is returned", 302, consentResponse.statusCode())
        assertThat(consentResponse.getHeader("location"), startsWith(flow.oidcService.fullAuthenticationRequestUrl))

        Response webTokenResponse = Steps.getWebTokenFromOidcService(flow, consentResponse)
        Map<String, String> webToken = webTokenResponse.body().jsonPath().getMap("\$.")
        String keyID = Steps.verifyTokenAndReturnSignedJwtObject(flow, webToken.get("id_token")).getHeader().getKeyID()
        assertThat(keyID, equalTo(flow.jwkSet.getKeys().get(0).getKeyID()))
    }

    @Unroll
    @Feature("OPENID_CONNECT")
    def "Request a token twice"() {
        expect:
        Response oidcServiceResponse = Steps.authWithMobileID(flow)
        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        assertEquals("Correct HTTP status code is returned", 302, consentResponse.statusCode())
        assertThat(consentResponse.getHeader("location"), startsWith(flow.oidcService.fullAuthenticationRequestUrl))
        Response oidcServiceResponse2 = Steps.followRedirectWithCookies(flow, consentResponse, flow.oidcService.cookies)
        assertEquals("Correct HTTP status code is returned", 302, oidcServiceResponse2.statusCode())
        // 1
        Response webTokenResponse = Steps.followRedirectWithCookies(flow, oidcServiceResponse2, flow.oidcClient.cookies)
        assertEquals("Correct HTTP status code is returned", 200, webTokenResponse.statusCode())
        // 2
        Response webTokenResponse2 = Steps.followRedirectWithCookies(flow, oidcServiceResponse2, flow.oidcClient.cookies)
        assertEquals("Correct HTTP status code is returned", 200, webTokenResponse2.statusCode())
        assertThat("Correct Content-Type is returned", webTokenResponse2.getContentType(), startsWith("application/json"))
        assertEquals("Correct error message is returned", "invalid_grant", webTokenResponse2.body().jsonPath().get("error"))
    }

    @Unroll
    @Feature("OPENID_CONNECT")
    def "Request with invalid scope"() {
        expect:
        Response response = Steps.createSession(flow, "wrongscope")
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        assertEquals("Correct error value", "invalid_scope", Utils.getParamValueFromResponseHeader(response, "error"))
        String errorDescription = URLDecoder.decode(Utils.getParamValueFromResponseHeader(response, "error_description"),StandardCharsets.UTF_8)
        assertThat("Correct error_description value", errorDescription, startsWith("The requested scope is invalid, unknown, or malformed"))
        String errorHint = URLDecoder.decode(Utils.getParamValueFromResponseHeader(response, "error_hint"),StandardCharsets.UTF_8)
        assertThat("Correct error_hint value", errorHint, startsWith("The OAuth 2.0 Client is not allowed to request scope"))
    }

    @Ignore // Etapp 4
    @Unroll
    @Feature("OPENID_CONNECT")
    def "Request with empty scope"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "response_type", RESPONSE_TYPE)
        def map2 = Utils.setParameter(paramsMap, "ui_locales", UI_LOCALE_ET)
        def map3 = Utils.setParameter(paramsMap, "client_id", flow.oidcClient.clientId)
        def map4 = Utils.setParameter(paramsMap, "redirect_uri", MOCK_URI)
        def map5 = Utils.setParameter(paramsMap, "state", Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        def map6 = Utils.setParameter(paramsMap, "nonce", Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        Response initOIDCServiceSession = Steps.createOIDCSessionWithParameters(flow , paramsMap)
        Response initLoginSession = Steps.createLoginSession(flow, initOIDCServiceSession)
        assertEquals("Correct HTTP status code is returned", 200, initLoginSession.statusCode())

        Response midInit = Requests.initMid(flow)
        assertEquals("Correct HTTP status code is returned", 200, midInit.statusCode())
        Response midPollResult = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 200, midPollResult.statusCode())
        Response acceptResponse = Requests.followRedirectWithSessionId(flow, REQUEST_TYPE_POST, flow.loginService.fullAuthAcceptUrl)
        assertEquals("Correct HTTP status code is returned", 302, acceptResponse.statusCode())

        Response oidcServiceResponse = Steps.getOAuthCookies(flow, acceptResponse)
        assertEquals("Correct HTTP status code is returned", 302, oidcServiceResponse.statusCode())

        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        assertEquals("Correct HTTP status code is returned", 302, consentResponse.statusCode())
        Response oidcserviceResponse = Steps.followRedirectWithCookies(flow, consentResponse, flow.oidcService.cookies)
        assertEquals("Correct HTTP status code is returned", 302, oidcserviceResponse.statusCode())

        Response webTokenResponse = Steps.followRedirectWithCookies(flow, oidcserviceResponse, flow.oidcClient.cookies)
        assertEquals("Correct HTTP status code is returned", 200, webTokenResponse.statusCode())
        Map<String, String> webToken = webTokenResponse.body().jsonPath().getMap("\$.")
    }

    @Unroll
    @Feature("OPENID_CONNECT")
    def "Request with invalid client"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "response_type", RESPONSE_TYPE)
        def map2 = Utils.setParameter(paramsMap, "ui_locales", UI_LOCALE_ET)
        def map3 = Utils.setParameter(paramsMap, "client_id", "my-old-client")
        def map4 = Utils.setParameter(paramsMap, "redirect_uri", MOCK_URI)
        def map5 = Utils.setParameter(paramsMap, "state", Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        def map6 = Utils.setParameter(paramsMap, "nonce", Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        def map7 = Utils.setParameter(paramsMap, "scope", DEFAULT_SCOPE)
        Response response = Requests.getRequestWithParams(flow , flow.oidcService.fullAuthenticationRequestUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        assertEquals("Correct error value", "invalid_client", Utils.getParamValueFromResponseHeader(response, "error"))
        String errorDescription = URLDecoder.decode(Utils.getParamValueFromResponseHeader(response, "error_description"),StandardCharsets.UTF_8)
        assertThat("Correct error_description value", errorDescription, startsWith("Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method"))
        String errorHint = URLDecoder.decode(Utils.getParamValueFromResponseHeader(response, "error_hint"),StandardCharsets.UTF_8)
        assertThat("Correct error_hint value", errorHint, startsWith("The requested OAuth 2.0 Client does not exist."))
    }

    @Unroll
    @Feature("OPENID_CONNECT")
    def "Request with invalid code"() {
        expect:
        Response oidcServiceResponse = Steps.authWithMobileID(flow)
        Response consentResponse = Steps.followRedirectWithSessionId(flow, oidcServiceResponse)
        assertEquals("Correct HTTP status code is returned", 302, consentResponse.statusCode())
        assertThat(consentResponse.getHeader("location"), startsWith(flow.oidcService.fullAuthenticationRequestUrl))
        Response oidcServiceResponse2 = Steps.followRedirectWithCookies(flow, consentResponse, flow.oidcService.cookies)
        assertEquals("Correct HTTP status code is returned", 302, oidcServiceResponse2.statusCode())

        HashMap<String, String> paramsMap = (HashMap)Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "scope", DEFAULT_SCOPE)
        def map2 = Utils.setParameter(paramsMap, "state", flow.state)
        def map4 = Utils.setParameter(paramsMap, "code", Utils.getParamValueFromResponseHeader(oidcServiceResponse2, "code") + "e")
        Response response = Requests.getRequestWithCookiesAndParams(flow, MOCK_URI , flow.oidcClient.cookies, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())
        assertThat("Correct Content-Type is returned", response.getContentType(), startsWith("application/json"))
        assertEquals("Correct error message is returned", "invalid_grant", response.body().jsonPath().get("error"))
    }
}
