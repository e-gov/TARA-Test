package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.commons.lang.RandomStringUtils
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
        Response initEidasAuthenticationSession = Steps.initEidasAuthSession(flow, flow.sessionId, COUNTRY, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initEidasAuthenticationSession.statusCode())
        assertEquals("Correct Content-Type is returned", "text/html;charset=UTF-8", initEidasAuthenticationSession.getContentType())
        String buttonLabel = initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@type == 'submit'}.@value")
        assertEquals("Continue button exists", "Continue", buttonLabel)
    }

    @Unroll
    @Feature("EIDAS_AUTH_INIT_ENDPOINT")
    @Feature("EIDAS_AUTH_INIT_REQUEST_CHECKS")
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
        _       | _         | _          || 400        || "missing country parameter" || "Required String parameter 'country' is not present"
        "bg"    | _         | _          || 400        || "country code is not in list" || "Antud riigikood ei ole lubatud. Lubatud riigikoodid on: CA"
        "BG"    | _         | _          || 400        || "capitalized country code is not in list" || "Antud riigikood ei ole lubatud. Lubatud riigikoodid on: CA"
        "ca"    | _         | _          || 400        || "country code must be capitalized" || "Antud riigikood ei ole lubatud. Lubatud riigikoodid on: CA"
        "F"     | _         | _          || 400        || "country code must be capitalized" || "Antud riigikood ei ole lubatud. Lubatud riigikoodid on: CA"
        "a1"     | _         | _          || 400        || "country code is not in list" || "Antud riigikood ei ole lubatud. Lubatud riigikoodid on: CA"
    }

    @Unroll
    @Feature("EIDAS_AUTH_INIT_ENDPOINT")
    def "initialize Eidas authentication without session ID"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map = Utils.setParameter(paramsMap, "country", COUNTRY)
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
        def map2 = Utils.setParameter(paramsMap, "country", COUNTRY)
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
        def map = Utils.setParameter(additionalParamsMap, "country", COUNTRY)
        Response initEidasAuthenticationSession = Steps.initEidasAuthSession(flow, flow.sessionId, COUNTRY, additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 400, initEidasAuthenticationSession.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", initEidasAuthenticationSession.getContentType())
        String errorMessage = "Multiple request parameters with the same name not allowed"
        assertThat(initEidasAuthenticationSession.body().jsonPath().get("message"), Matchers.containsString(errorMessage))
    }

    @Unroll
    @Feature("AUTH_INIT_WITH_EIDASONLY_AND_COUNTRY")
    def "initialize Eidas authentication with scope: #scope and description #label"() {
        expect:
        Response response = Steps.startAuthenticationInTara(flow, scope, "et", false)
        assertEquals("Correct HTTP status code is returned", statusCode, response.statusCode())
        String formUrl = response.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action")
        assertThat("Correct domestic connector service url form", formUrl, equalTo(flow.domesticConnectorService.fullAuthenticationRequestUrl.toString()))
        String eidasCountry = response.body().htmlPath().getString("**.find { it.@name == 'country' }.@value")
        assertThat("Correct Eidas country is selected", eidasCountry, equalTo(expectedCountry))

        where:
        scope                                                        || statusCode || expectedCountry || label
        "openid eidas:country:ca eidasonly"                          || 200        || "CA" || "direct redirection into ca Eidas network"
        "openid eidasonly eidas:country:ca"                          || 200        || "CA" || "direct redirection into ca Eidas network"
        "openid smartid eidasonly eidas:country:ca"                  || 200        || "CA" || "direct redirection into ca Eidas network"
        // TARA2-121 "openid smartid eidasonly eidas:country:ca eidas:country:de" || 200        || "CA" || "direct redirection into ca Eidas network"
        // TARA2-121   "openid smartid eidasonly eidas:country:DE eidas:country:ca" || 200        || "CA" || "direct redirection into ca Eidas network"
        // TARA2-121    "openid smartid eidasonly eidas:country:de eidas:country:ca" || 200        || "DE" || "direct redirection into ca Eidas network"
    }

    @Unroll
    @Feature("AUTH_INIT_WITH_EIDASONLY_AND_COUNTRY")
    def "initialize Eidas authentication with eidas scope: #label"() {
        expect:
        Response response = Steps.startAuthenticationInTara(flow, scope, "et", false)
        assertEquals("Correct HTTP status code is returned", statusCode, response.statusCode())
        assertTrue(response.htmlPath().getInt("**.findAll { it.'@data-tab' == '"+ authType +"' }.size()") > 0)

        where:
        scope                                                        || statusCode || authType || label
        "openid smartid eidas:country:ca"                            || 200        || "smart-id" || "Smart-ID in TARA selection"
// TARA2-121       "openid eidasonly eidas:country:"                            || 200        || "eu-citizen" || "Eidas in TARA selection"
// TARA2-121       "openid eidasonly eidas:country:gb"                          || 200        || "eu-citizen" || "Eidas in TARA selection"
    }

    @Unroll
    @Feature("EIDAS_AUTH_CALLBACK_REQUEST_CHECKS")
    def "Eidas callback request. Use relayState twice"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        Response initEidasAuthenticationSession = Steps.initEidasAuthSession(flow, flow.sessionId, COUNTRY, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initEidasAuthenticationSession.statusCode())
        assertEquals("Correct Content-Type is returned", "text/html;charset=UTF-8", initEidasAuthenticationSession.getContentType())
        String buttonLabel = initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@type == 'submit'}.@value")
        assertEquals("Continue button exists", "Continue", buttonLabel)

        flow.setNextEndpoint(initEidasAuthenticationSession.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response colleagueResponse = Steps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA)
        Response authorizationResponse = Steps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        // 1
        Steps.eidasRedirectAuthorizationResponse(flow, authorizationResponse)
        // 2
        Response redirectionResponse2 = Steps.eidasRedirectAuthorizationResponse(flow, authorizationResponse, false)
        assertEquals("Correct HTTP status code is returned", 400, redirectionResponse2.statusCode())
        assertThat("Correct Content-Type is returned", redirectionResponse2.getContentType(), Matchers.startsWith("application/json"))
        assertEquals("Correct error is returned", "Bad Request", redirectionResponse2.body().jsonPath().get("error"))
        assertThat("Correct error message is returned", redirectionResponse2.body().jsonPath().getString("message"), Matchers.endsWith("Ebakorrektne päring. Vale sessiooni staatus."))
        assertTrue(redirectionResponse2.body().jsonPath().get("incident_nr").toString().size() > 15)
    }

    @Unroll
    @Feature("EIDAS_AUTH_CALLBACK_ENDPOINT")
    def "Authentication with Eidas. Callback with multiple param values #label"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        Response initEidasAuthenticationSession = Steps.initEidasAuthSession(flow, flow.sessionId, COUNTRY, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initEidasAuthenticationSession.statusCode())
        assertEquals("Correct Content-Type is returned", "text/html;charset=UTF-8", initEidasAuthenticationSession.getContentType())
        String buttonLabel = initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@type == 'submit'}.@value")
        assertEquals("Continue button exists", "Continue", buttonLabel)

        flow.setNextEndpoint(initEidasAuthenticationSession.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response colleagueResponse = Steps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA)
        Response response = Steps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        String endpointUrl = response.body().htmlPath().get("**.find {it.@method == 'post'}.@action")
        String samlResponse = response.body().htmlPath().get("**.find {it.@name == 'SAMLResponse'}.@value")
        String relayState = response.body().htmlPath().get("**.find {it.@name == 'RelayState'}.@value")

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "SAMLResponse" , samlResponse)
        Utils.setParameter(paramsMap, "RelayState", relayState)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        def map = Utils.setParameter(additionalParamsMap, paramName, paramValue)
        Response redirectionResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap, additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 400, redirectionResponse.statusCode())
        assertThat("Correct Content-Type is returned", redirectionResponse.getContentType(), Matchers.startsWith("application/json"))
        assertEquals("Correct error is returned", "Bad Request", redirectionResponse.body().jsonPath().get("error"))
        assertThat("Correct error message is returned", redirectionResponse.body().jsonPath().getString("message"), Matchers.startsWith(errorMessage))
        assertTrue(redirectionResponse.body().jsonPath().get("incident_nr").toString().size() > 15)
        assertEquals("Correct path is returned", flow.loginService.eidasCallbackUrl, redirectionResponse.body().jsonPath().get("path"))

        where:
        paramName      | paramValue                                                                          || label                || errorMessage
        "RelayState"   | "1XyyAocKwZp8Zp8qd9lhVKiJPF1AywyfpXTLqYGLFE73CKcEgSKOrfVq9UMfX9HAfWwBJMI9O7Bm22BZ1" || "relayState twice"   || "Multiple request parameters with the same name not allowed"
        "SAMLResponse" | "1XyyAocKwZp8Zp8qd9lhVKiJPF1AywyfpXTLqYGLFE73CKcEgSKOrfVq9UMfX9HAfWwBJMI9O7Bm22BZ1" || "SAMLResponse twice" || "Multiple request parameters with the same name not allowed"
    }

    @Unroll
    @Feature("EIDAS_AUTH_CALLBACK_ENDPOINT")
    def "Authentication with Eidas. Callback with missing params #label"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        Response initEidasAuthenticationSession = Steps.initEidasAuthSession(flow, flow.sessionId, COUNTRY, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initEidasAuthenticationSession.statusCode())
        assertEquals("Correct Content-Type is returned", "text/html;charset=UTF-8", initEidasAuthenticationSession.getContentType())
        String buttonLabel = initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@type == 'submit'}.@value")
        assertEquals("Continue button exists", "Continue", buttonLabel)

        flow.setNextEndpoint(initEidasAuthenticationSession.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response colleagueResponse = Steps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA)
        Response response = Steps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        String endpointUrl = response.body().htmlPath().get("**.find {it.@method == 'post'}.@action")
        String samlResponse = response.body().htmlPath().get("**.find {it.@name == 'SAMLResponse'}.@value")
        String relayState = response.body().htmlPath().get("**.find {it.@name == 'RelayState'}.@value")

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, paramName1 , samlResponse)
        def map2 = Utils.setParameter(paramsMap, paramName2, relayState)
        Response redirectionResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 400, redirectionResponse.statusCode())
        assertThat("Correct Content-Type is returned", redirectionResponse.getContentType(), Matchers.startsWith("application/json"))
        assertEquals("Correct error is returned", "Bad Request", redirectionResponse.body().jsonPath().get("error"))
        assertThat("Correct error message is returned", redirectionResponse.body().jsonPath().getString("message"), Matchers.startsWith(errorMessage))
        assertTrue(redirectionResponse.body().jsonPath().get("incident_nr").toString().size() > 15)

        where:
        paramName1     | paramName2   || label          || errorMessage
        "SAMLResponse" | _            || "RelayState"   || "Required String parameter 'RelayState' is not present"
        _              | "RelayState" || "SAMLResponse" || "Required String parameter 'SAMLResponse' is not present"
    }

    @Unroll
    @Feature("EIDAS_AUTH_CALLBACK_ENDPOINT")
    def "Authentication with Eidas. Callback with invalid #label"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        Response initEidasAuthenticationSession = Steps.initEidasAuthSession(flow, flow.sessionId, COUNTRY, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 200, initEidasAuthenticationSession.statusCode())
        assertEquals("Correct Content-Type is returned", "text/html;charset=UTF-8", initEidasAuthenticationSession.getContentType())
        String buttonLabel = initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@type == 'submit'}.@value")
        assertEquals("Continue button exists", "Continue", buttonLabel)

        flow.setNextEndpoint(initEidasAuthenticationSession.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response colleagueResponse = Steps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA)
        Response response = Steps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        String endpointUrl = response.body().htmlPath().get("**.find {it.@method == 'post'}.@action")
        String samlResponse = response.body().htmlPath().get("**.find {it.@name == 'SAMLResponse'}.@value")
        String relayState = response.body().htmlPath().get("**.find {it.@name == 'RelayState'}.@value")

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        if (samlResponseValue == "default") {
            def map1 = Utils.setParameter(paramsMap, "SAMLResponse", samlResponse)
        } else {
            def map1 = Utils.setParameter(paramsMap, "SAMLResponse", samlResponseValue)
        }
        if (relayStateValue == "default") {
            def map2 = Utils.setParameter(paramsMap, "RelayState", relayState)
        } else {
            def map2 = Utils.setParameter(paramsMap, "RelayState", relayStateValue)
        }
        Response redirectionResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", statusCode, redirectionResponse.statusCode())
        assertThat("Correct Content-Type is returned", redirectionResponse.getContentType(), Matchers.startsWith("application/json"))
        assertEquals("Correct error is returned", error, redirectionResponse.body().jsonPath().get("error"))
        assertThat("Correct error message is returned", redirectionResponse.body().jsonPath().getString("message"), Matchers.startsWith(errorMessage))
        assertTrue(redirectionResponse.body().jsonPath().get("incident_nr").toString().size() > 15)

        where:
        samlResponseValue                           | relayStateValue || statusCode || error                   || label                      || errorMessage
        "AB-"                                       | "default"       || 500        || "Internal Server Error" || "SAMLResponse short value" || "Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."
        RandomStringUtils.random(11000, true, true) | "default"       || 500        || "Internal Server Error" || "SAMLResponse long value"  || "Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."
        "default"                                   | "-DC@"          || 400        || "Bad Request"           || "RelayState short value"   || "Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."

    }
}
