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
import static org.junit.jupiter.api.Assertions.*
import static org.hamcrest.MatcherAssert.assertThat

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
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.sessionId, COUNTRY, Collections.emptyMap())
        assertEquals(200, initEidasAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", initEidasAuthenticationSession.getContentType(), "Correct Content-Type is returned")
        String buttonLabel = initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@type == 'submit'}.@value")
        assertEquals("Continue", buttonLabel, "Continue button exists")
    }

    @Unroll
    @Feature("EIDAS_AUTH_INIT_ENDPOINT")
    @Feature("EIDAS_AUTH_INIT_REQUEST_CHECKS")
    def "initialize Eidas authentication with #label"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        def map = Utils.setParameter(additionalParamsMap, paramName, paramValue)
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.sessionId, country, additionalParamsMap)
        assertEquals(statusCode, initEidasAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", initEidasAuthenticationSession.getContentType(), "Correct Content-Type is returned")
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
        Response response = Requests.postRequestWithParams(flow, flow.loginService.fullEidasInitUrl, paramsMap, Collections.emptyMap())
        assertEquals(403, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertEquals("Keelatud päring. Päring esitati topelt, sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"), "Correct error message is returned")
    }

    @Ignore //TARA2-165
    @Unroll
    @Feature("EIDAS_AUTH_INIT_ENDPOINT")
    def "initialize Eidas authentication with invalid method get"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        def map = Utils.setParameter(cookiesMap, "SESSION", flow.sessionId)
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(paramsMap, "country", COUNTRY)
        def map3 = Utils.setParameter(paramsMap, "_csrf", flow.csrf)
        Response response = Requests.getRequestWithCookiesAndParams(flow,
                flow.loginService.fullEidasInitUrl,
                cookiesMap,
                paramsMap,
                Collections.emptyMap())
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertThat(response.body().jsonPath().get("message").toString(), equalTo("Request method 'GET' not supported"))
    }

    @Unroll
    @Feature("EIDAS_AUTH_INIT_ENDPOINT")
    def "initialize Eidas authentication with multiple parameters"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        def map = Utils.setParameter(additionalParamsMap, "country", COUNTRY)
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.sessionId, COUNTRY, additionalParamsMap)
        assertEquals(400, initEidasAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", initEidasAuthenticationSession.getContentType(), "Correct Content-Type is returned")
        String errorMessage = "Multiple request parameters with the same name not allowed"
        assertThat(initEidasAuthenticationSession.body().jsonPath().get("message"), Matchers.containsString(errorMessage))
    }

    @Unroll
    @Feature("AUTH_INIT_WITH_EIDASONLY_AND_COUNTRY")
    def "initialize Eidas authentication with scope: #scope and description #label"() {
        expect:
        Response response = Steps.startAuthenticationInTara(flow, scope, "et", false)
        assertEquals(statusCode, response.statusCode(), "Correct HTTP status code is returned")
        String formUrl = response.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action")
        assertThat("Correct domestic connector service url form", formUrl, equalTo(flow.loginService.eidasInitUrl.toString()))
        String eidasCountry = response.body().htmlPath().getString("**.find { it.@name == 'country' }.@value")
        assertThat("Correct Eidas country is selected", eidasCountry, equalTo(expectedCountry))

        where:
        scope                                                        || statusCode || expectedCountry || label
        "openid eidas:country:ca eidasonly"                          || 200        || "CA" || "direct redirection into ca Eidas network"
        "openid eidasonly eidas:country:ca"                          || 200        || "CA" || "direct redirection into ca Eidas network"
        "openid smartid eidasonly eidas:country:ca"                  || 200        || "CA" || "direct redirection into ca Eidas network"
        // TARA2-121 TARA2-223 "openid smartid eidasonly eidas:country:ca eidas:country:de" || 200        || "CA" || "direct redirection into ca Eidas network"
        //    "openid smartid eidasonly eidas:country:DE eidas:country:ca" || 200        || "CA" || "direct redirection into ca Eidas network"
        //     "openid smartid eidasonly eidas:country:de eidas:country:ca" || 200        || "DE" || "direct redirection into ca Eidas network"
    }

    @Unroll
    @Feature("AUTH_INIT_WITH_EIDASONLY_AND_COUNTRY")
    def "initialize Eidas authentication with eidas scope: #label"() {
        expect:
        Response response = Steps.startAuthenticationInTara(flow, scope, "et", false)
        assertEquals(statusCode, response.statusCode(), "Correct HTTP status code is returned")
        assertTrue(response.htmlPath().getInt("**.findAll { it.'@data-tab' == '"+ authType +"' }.size()") > 0)

        where:
        scope                                                        || statusCode || authType || label
        "openid smartid eidas:country:ca"                            || 200        || "smart-id" || "Smart-ID in TARA selection"
        // TARA2-121  TARA2-223 "openid eidasonly eidas:country:"                            || 200        || "eu-citizen" || "Eidas in TARA selection"
        //      "openid eidasonly eidas:country:gb"                          || 200        || "eu-citizen" || "Eidas in TARA selection"
    }

    @Unroll
    @Feature("EIDAS_AUTH_CALLBACK_REQUEST_CHECKS")
    def "Eidas callback request. Use relayState twice"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.sessionId, COUNTRY, Collections.emptyMap())
        assertEquals(200, initEidasAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", initEidasAuthenticationSession.getContentType(), "Correct Content-Type is returned")
        String buttonLabel = initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@type == 'submit'}.@value")
        assertEquals("Continue", buttonLabel, "Continue button exists")

        flow.setNextEndpoint(initEidasAuthenticationSession.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA)
        Response authorizationResponse = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        // 1
        EidasSteps.eidasRedirectAuthorizationResponse(flow, authorizationResponse)
        // 2
        Response redirectionResponse2 = EidasSteps.eidasRedirectAuthorizationResponse(flow, authorizationResponse, false)
        assertEquals(400, redirectionResponse2.statusCode(), "Correct HTTP status code is returned")
        assertThat("Correct Content-Type is returned", redirectionResponse2.getContentType(), Matchers.startsWith("application/json"))
        assertEquals("Bad Request", redirectionResponse2.body().jsonPath().get("error"), "Correct error is returned")
        assertThat("Correct error message is returned", redirectionResponse2.body().jsonPath().getString("message"), Matchers.endsWith("Ebakorrektne päring."))
        assertTrue(redirectionResponse2.body().jsonPath().get("incident_nr").toString().size() > 15)
    }

    @Unroll
    @Feature("EIDAS_AUTH_CALLBACK_ENDPOINT")
    def "Authentication with Eidas. Callback with multiple param values #label"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.sessionId, COUNTRY, Collections.emptyMap())
        assertEquals(200, initEidasAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", initEidasAuthenticationSession.getContentType(), "Correct Content-Type is returned")
        String buttonLabel = initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@type == 'submit'}.@value")
        assertEquals("Continue", buttonLabel, "Continue button exists")

        flow.setNextEndpoint(initEidasAuthenticationSession.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA)
        Response response = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        String endpointUrl = response.body().htmlPath().get("**.find {it.@method == 'post'}.@action")
        String samlResponse = response.body().htmlPath().get("**.find {it.@name == 'SAMLResponse'}.@value")
        String relayState = response.body().htmlPath().get("**.find {it.@name == 'RelayState'}.@value")

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramsMap, "SAMLResponse" , samlResponse)
        Utils.setParameter(paramsMap, "RelayState", relayState)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        def map = Utils.setParameter(additionalParamsMap, paramName, paramValue)
        Response redirectionResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap, additionalParamsMap)
        assertEquals(400, redirectionResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat("Correct Content-Type is returned", redirectionResponse.getContentType(), Matchers.startsWith("application/json"))
        assertEquals("Bad Request", redirectionResponse.body().jsonPath().get("error"), "Correct error is returned")
        assertThat("Correct error message is returned", redirectionResponse.body().jsonPath().getString("message"), Matchers.startsWith(errorMessage))
        assertTrue(redirectionResponse.body().jsonPath().get("incident_nr").toString().size() > 15)
        assertEquals(flow.loginService.eidasCallbackUrl, redirectionResponse.body().jsonPath().get("path"), "Correct path is returned")

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
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.sessionId, COUNTRY, Collections.emptyMap())
        assertEquals(200, initEidasAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", initEidasAuthenticationSession.getContentType(), "Correct Content-Type is returned")
        String buttonLabel = initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@type == 'submit'}.@value")
        assertEquals("Continue", buttonLabel, "Continue button exists")

        flow.setNextEndpoint(initEidasAuthenticationSession.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA)
        Response response = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        String endpointUrl = response.body().htmlPath().get("**.find {it.@method == 'post'}.@action")
        String samlResponse = response.body().htmlPath().get("**.find {it.@name == 'SAMLResponse'}.@value")
        String relayState = response.body().htmlPath().get("**.find {it.@name == 'RelayState'}.@value")

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, paramName1 , samlResponse)
        def map2 = Utils.setParameter(paramsMap, paramName2, relayState)
        Response redirectionResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap, Collections.emptyMap())
        assertEquals(400, redirectionResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat("Correct Content-Type is returned", redirectionResponse.getContentType(), Matchers.startsWith("application/json"))
        assertEquals("Bad Request", redirectionResponse.body().jsonPath().get("error"), "Correct error is returned")
        assertThat("Correct error message is returned", redirectionResponse.body().jsonPath().getString("message"), Matchers.startsWith(errorMessage))
        assertTrue(redirectionResponse.body().jsonPath().get("incident_nr").toString().size() > 15)

        where:
        paramName1     | paramName2   || label          || errorMessage
        "SAMLResponse" | _            || "RelayState"   || "Required String parameter 'RelayState' is not present"
        _              | "RelayState" || "SAMLResponse" || "Required String parameter 'SAMLResponse' is not present"
    }

    @Feature("EIDAS_AUTH_CALLBACK_ENDPOINT")
    def "Authentication with Eidas. Invalid password"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        String country = "CA"
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.sessionId, country, Collections.emptyMap())
        assertEquals(200, initEidasAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", initEidasAuthenticationSession.getContentType(), "Correct Content-Type is returned")
        String buttonLabel = initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@type == 'submit'}.@value")
        assertEquals("Continue", buttonLabel, "Continue button exists")

        flow.setNextEndpoint(initEidasAuthenticationSession.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response authorizationResponse = EidasSteps.continueEidasFlow(flow, IDP_USERNAME, "myPassword", EIDASLOA)
        String endpointUrl = authorizationResponse.body().htmlPath().getString("**.find { it.@id == 'redirectForm' }.@action")
        String token = authorizationResponse.body().htmlPath().getString("**.find { it.@id == 'token' }.@value")
        Response eidasProxyResponse2 = EidasSteps.eidasProxyServiceRequest(flow, endpointUrl, token)
        Response colleagueResponse = EidasSteps.eidasColleagueResponse(flow, eidasProxyResponse2)
        Response authorizationResponse2 = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        Response redirectionResponse = EidasSteps.eidasRedirectAuthorizationResponse(flow, authorizationResponse2, false)
        assertEquals(400, redirectionResponse.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", redirectionResponse.getContentType(), "Correct Content-Type is returned")
        assertThat(redirectionResponse.body().jsonPath().get("message").toString(), equalTo("Eidas autentimine ebaõnnestus."))
    }


    @Unroll
    @Feature("EIDAS_AUTH_CALLBACK_ENDPOINT")
    def "Authentication with Eidas. Callback with invalid #label"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.sessionId, COUNTRY, Collections.emptyMap())
        assertEquals(200, initEidasAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", initEidasAuthenticationSession.getContentType(), "Correct Content-Type is returned")
        String buttonLabel = initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@type == 'submit'}.@value")
        assertEquals("Continue", buttonLabel, "Continue button exists")

        flow.setNextEndpoint(initEidasAuthenticationSession.body().htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.body().htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA)
        Response response = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
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
        assertEquals(statusCode, redirectionResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat("Correct Content-Type is returned", redirectionResponse.getContentType(), Matchers.startsWith("application/json"))
        assertEquals(error, redirectionResponse.body().jsonPath().get("error"), "Correct error is returned")
        assertThat("Correct error message is returned", redirectionResponse.body().jsonPath().getString("message"), Matchers.startsWith(errorMessage))
        assertTrue(redirectionResponse.body().jsonPath().get("incident_nr").toString().size() > 15)

        where:
        samlResponseValue                           | relayStateValue || statusCode || error                   || label                      || errorMessage
        "AB-"                                       | "default"       || 500        || "Internal Server Error" || "SAMLResponse short value" || "Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."
        RandomStringUtils.random(11000, true, true) | "default"       || 500        || "Internal Server Error" || "SAMLResponse long value"  || "Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."
        "default"                                   | "DC@"          || 400        || "Bad Request"           || "RelayState short value"   || "Ebakorrektne päring."

    }
}
