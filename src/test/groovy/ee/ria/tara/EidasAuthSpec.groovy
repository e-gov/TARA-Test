package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Ignore
import spock.lang.IgnoreIf
import spock.lang.Unroll
import org.hamcrest.Matchers

import static org.hamcrest.Matchers.equalTo
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat
import static org.junit.Assert.assertTrue

@IgnoreIf({ properties['test.deployment.env'] == "idp" })
class EidasAuthSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Unroll
    @Feature("EIDAS_AUTH_INIT_ENDPOINT")
    def "initialize Eidas authentication"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        Response initEidasAuthenticationSession = Steps.initEidasAuthSession(flow, flow.sessionId, "CA", Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initEidasAuthenticationSession.statusCode())
        assertEquals("Correct Content-Type is returned", "text/html;charset=UTF-8", initEidasAuthenticationSession.getContentType())
        String buttonLabel = initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@type == 'submit'}.@value")
        assertEquals("Continue button exists", "Continue", buttonLabel)
    }

    @Unroll
    @Feature("EIDAS_AUTH_INIT_ENDPOINT")
    def "initialize Eidas authentication with #label"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        def map = Utils.setParameter(additionalParamsMap, paramName, paramValue)
        Response initEidasAuthenticationSession = Steps.initEidasAuthSession(flow, flow.sessionId, country, additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", statusCode, initEidasAuthenticationSession.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", initEidasAuthenticationSession.getContentType())
        assertThat(initEidasAuthenticationSession.body().jsonPath().getString("message"), Matchers.containsString(errorMessage))
        assertTrue(initEidasAuthenticationSession.body().jsonPath().get("incident_nr").toString().size() > 15)

        where:
        country | paramName | paramValue || statusCode || label                       || errorMessage
    //    _       | _         | _          || 400        || "missing country parameter" || "Required String parameter 'country' is not present"
        "bg"    | _         | _          || 400        || "country code is not in list" || "Antud riigikood ei ole lubatud. Lubatud riigikoodid on: CA"
        "BG"    | _         | _          || 400        || "capitalized country code is not in list" || "Antud riigikood ei ole lubatud. Lubatud riigikoodid on: CA"
        "ca"    | _         | _          || 400        || "country code must be capitalized" || "Antud riigikood ei ole lubatud. Lubatud riigikoodid on: CA"
        "F"     | _         | _          || 400        || "country code must be capitalized" || "Antud riigikood ei ole lubatud. Lubatud riigikoodid on: CA"
    }

    @Unroll
    @Feature("EIDAS_AUTH_INIT_ENDPOINT")
    def "initialize Eidas authentication without session ID"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map = Utils.setParameter(paramsMap, "country", "CA")
        Response response = Requests.getRequestWithParams(flow, flow.loginService.fullEidasInitUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertEquals("Correct error message is returned", "Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"))
    }

    @Ignore //TARA2-165
    @Unroll
    @Feature("EIDAS_AUTH_INIT_ENDPOINT")
    def "initialize Eidas authentication with invalid method post"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        def map = Utils.setParameter(cookiesMap, "SESSION", flow.sessionId)
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(paramsMap, "country", "CA")
        def map3 = Utils.setParameter(paramsMap, "_csrf", flow.csrf)
        Response response = Requests.postRequestWithCookiesAndParams(flow,
                flow.loginService.fullEidasInitUrl,
                cookiesMap,
                paramsMap,
                Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), equalTo("Request method 'POST' not supported"))
    }

    @Unroll
    @Feature("EIDAS_AUTH_INIT_ENDPOINT")
    def "initialize Eidas authentication with multiple parameters"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        def map = Utils.setParameter(additionalParamsMap, "country", "CA")
        Response initEidasAuthenticationSession = Steps.initEidasAuthSession(flow, flow.sessionId, "CA", additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 400, initEidasAuthenticationSession.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", initEidasAuthenticationSession.getContentType())
        String errorMessage = "Multiple request parameters with the same name not allowed"
        assertThat(initEidasAuthenticationSession.body().jsonPath().get("message"), Matchers.containsString(errorMessage))
    }

 //   @Ignore // TARA2-121
    @Unroll
    @Feature("AUTH_INIT_WITH_EIDASONLY_AND_COUNTRY")
    def "initialize Eidas authentication with eidasonly scope: #label"() {
        expect:
        Response response = Steps.startAuthenticationInTara(flow, scope, "et", false)
        assertEquals("Correct HTTP status code is returned", statusCode, response.statusCode())
        assertThat("Redirection to Eidas init endpoint", response.getHeader("location"), Matchers.containsString("/auth/eidas/init"))

        where:
        scope                                                        || statusCode || label
        "openid eidas:country:ca eidasonly"                          || 302        || "direct redirection into ca Eidas network"
        "openid eidasonly eidas:country:ca"                          || 302        || "direct redirection into ca Eidas network"
        "openid smartid eidasonly eidas:country:ca"                  || 302        || "direct redirection into ca Eidas network"
        "openid smartid eidasonly eidas:country:ca eidas:country:fi" || 302        || "direct redirection into ca Eidas network"
        "openid smartid eidasonly eidas:country:CA eidas:country:fi" || 302        || "direct redirection into fi Eidas network"
        "openid smartid eidasonly eidas:country:fi eidas:country:ca" || 302        || "direct redirection into fi Eidas network"
        "openid smartid eidas:country:ca"                            || 302        || "Smart-ID in TARA selection"
        "openid eidasonly eidas:country:"                            || 302        || "Eidas in TARA selection"
        "openid eidasonly eidas:country:gb"                          || 302        || "Eidas in TARA selection"
    }


}
