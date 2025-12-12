package ee.ria.tara

import com.microsoft.playwright.Page
import com.microsoft.playwright.Request
import com.microsoft.playwright.options.LoadState
import com.microsoft.playwright.options.WaitForSelectorState
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import ee.ria.tara.frontend.AuthInitPage
import ee.ria.tara.frontend.SidInitPage
import ee.ria.tara.model.Client
import ee.ria.tara.model.SidAccount
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import java.util.function.Predicate

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is

class UserFlowSmokeSpec extends PlaywrightSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    def "Authentication with Smart-ID"() {
        given:
        Client client = ClientStore.mockPublic

        when:
        AuthInitPage authInitPage = new AuthInitPage(page, flow)
        authInitPage.openAuthInit(client)

        // TODO: SidAccount or its person code?
        authInitPage.initSidAuth(SidAccount.EE40404049996.personCode)

        // TODO: how to get rid of it?
        SidInitPage sidInitPage = new SidInitPage(page, flow)
        String authorizationCode = sidInitPage.waitForAuthorizationCode(client)

        Response tokenResponse = Requests.webTokenBasicRequest(flow, authorizationCode)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience[0], is(client.clientId))
        assertThat("Correct subject", claims.subject, is("EE40404049996"))
    }
}
