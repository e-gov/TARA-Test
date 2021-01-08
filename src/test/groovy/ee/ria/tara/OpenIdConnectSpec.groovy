package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.hamcrest.Matchers
import spock.lang.Unroll
import com.nimbusds.jose.jwk.JWKSet

import static org.hamcrest.Matchers.equalTo
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat

class OpenIdConnectSpec extends TaraSpecification {
    Flow flow = new Flow(props)

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
        assertThat(consentResponse.getHeader("location"), Matchers.startsWith(flow.oidcService.fullAuthenticationRequestUrl))

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
        assertThat(consentResponse.getHeader("location"), Matchers.startsWith(flow.oidcService.fullAuthenticationRequestUrl))

        Response webTokenResponse = Steps.getWebTokenFromOidcService(flow, consentResponse)
    }

}
