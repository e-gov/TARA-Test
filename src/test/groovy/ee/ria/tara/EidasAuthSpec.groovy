package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.commons.lang3.RandomStringUtils

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.greaterThan
import static org.hamcrest.Matchers.hasLength
import static org.hamcrest.Matchers.is

class EidasAuthSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Feature("EIDAS_AUTH_INIT_ENDPOINT")
    def "initialize eIDAS authentication"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid eidas")

        when:
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.sessionId, COUNTRY_CA, [:])

        then:
        assertThat("Correct HTTP status code", initEidasAuthenticationSession.statusCode, is(200))
        assertThat("Correct Content-Type", initEidasAuthenticationSession.contentType, is("text/html;charset=UTF-8"))
        String buttonLabel = initEidasAuthenticationSession.htmlPath().getString('**.find { input -> input.@type == \'submit\'}.@value')
        assertThat("Continue button exists", buttonLabel, is("Continue"))
    }

    @Feature("EIDAS_AUTH_INIT_ENDPOINT")
    @Feature("EIDAS_AUTH_INIT_REQUEST_CHECKS")
    def "initialize eIDAS authentication with #label"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid eidas")

        when:
        Response response = EidasSteps.initEidasAuthSession(flow, flow.sessionId, country, [:])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat(response.jsonPath().getString('message'), is(errorMessage))
        assertThat("Incident number is present", response.jsonPath().getString("incident_nr"), hasLength(32))

        where:
        country | label                                     || errorMessage
        _       | "missing country parameter"               || "Required request parameter 'country' for method parameter type String is not present"
        "bg"    | "country code is not in list"             || "Antud riigikood ei ole lubatud. Lubatud riigikoodid on:<span translate=\"no\"> CA, DE</span>"
        "BG"    | "capitalized country code is not in list" || "Antud riigikood ei ole lubatud. Lubatud riigikoodid on:<span translate=\"no\"> CA, DE</span>"
        "ca"    | "country code must be capitalized"        || "Antud riigikood ei ole lubatud. Lubatud riigikoodid on:<span translate=\"no\"> CA, DE</span>"
        "F"     | "country code must be capitalized"        || "Antud riigikood ei ole lubatud. Lubatud riigikoodid on:<span translate=\"no\"> CA, DE</span>"
        "a1"    | "country code is not in list"             || "Antud riigikood ei ole lubatud. Lubatud riigikoodid on:<span translate=\"no\"> CA, DE</span>"
    }

    @Feature("EIDAS_AUTH_INIT_ENDPOINT")
    def "initialize eIDAS authentication without session ID"() {
        given:
        Map paramsMap = ["country": COUNTRY_CA]

        when:
        Response response = Requests.postRequestWithParams(flow, flow.loginService.fullEidasInitUrl, paramsMap, [:])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(403))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString("message"), is(MESSAGE_FORBIDDEN_REQUEST))
    }

    //TODO: AUT-630
    @Feature("EIDAS_AUTH_INIT_ENDPOINT")
    def "initialize eIDAS authentication with invalid method get"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        Map cookiesMap = ["SESSION": flow.sessionId]
        Map paramsMap = [
                "country": COUNTRY_CA,
                "_csrf"  : flow.csrf]

        when:
        Response response = Requests.getRequestWithCookiesAndParams(flow, flow.loginService.fullEidasInitUrl, cookiesMap, paramsMap, [:])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString("message"), is(MESSAGE_INTERNAL_ERROR))
    }

    @Feature("EIDAS_AUTH_INIT_ENDPOINT")
    def "initialize eIDAS authentication with multiple parameters"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        Map additionalParamsMap = ["country": COUNTRY_CA]

        when:
        Response response = EidasSteps.initEidasAuthSession(flow, flow.sessionId, COUNTRY_CA, additionalParamsMap)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString("message"), is(MESSAGE_DUPLICATE_PARAMETERS))
    }

    @Feature("AUTH_INIT_WITH_EIDASONLY_AND_COUNTRY")
    def "initialize eIDAS authentication with scope: #scope and redirect into CA eIDAS network"() {
        when:
        Response response = Steps.startAuthenticationInTara(flow, scope, "et", false)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        String formUrl = response.htmlPath().getString("**.find { form -> form.@method == 'post' }.@action")
        assertThat("Correct domestic connector service url form", formUrl, is(flow.loginService.eidasInitUrl))
        String eidasCountry = response.htmlPath().getString("**.find { it.@name == 'country' }.@value")
        assertThat("Correct Eidas country is selected", eidasCountry, is(expectedCountry))

        where:
        scope                                                        || expectedCountry
        "openid eidas:country:ca eidasonly"                          || COUNTRY_CA
        "openid eidasonly eidas:country:ca"                          || COUNTRY_CA
        "openid smartid eidasonly eidas:country:ca"                  || COUNTRY_CA
        "openid smartid eidasonly eidas:country:ca eidas:country:de" || COUNTRY_CA
        "openid smartid eidasonly eidas:country:DE eidas:country:ca" || COUNTRY_CA
        "openid smartid eidasonly eidas:country:de eidas:country:ca" || "DE"
    }

    @Feature("AUTH_INIT_WITH_EIDASONLY_AND_COUNTRY")
    def "initialize eIDAS authentication with eIDAS scope: #label"() {
        when:
        Response response = Steps.startAuthenticationInTara(flow, scope, "et", false)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        assertThat(response.htmlPath().getInt("**.findAll { it.'@data-tab' == '" + authType + "' }.size()"), is(greaterThan(0)))

        where:
        scope                               || statusCode || authType     || label
        "openid smartid eidas:country:ca"   || 200        || "smart-id"   || "Smart-ID in TARA selection"
        "openid eidasonly eidas:country:gb" || 200        || "eu-citizen" || "Eidas in TARA selection"
    }

    @Feature("EIDAS_AUTH_CALLBACK_REQUEST_CHECKS")
    def "eIDAS callback request. Use relayState twice"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.sessionId, COUNTRY_CA, [:])

        flow.setNextEndpoint(initEidasAuthenticationSession.htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA_HIGH)
        Response authorizationResponse = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        // 1
        EidasSteps.eidasRedirectAuthorizationResponse(flow, authorizationResponse)

        when:
        // 2
        Response redirectionResponse2 = EidasSteps.eidasRedirectAuthorizationResponse(flow, authorizationResponse, false)

        then:
        assertThat("Correct HTTP status code", redirectionResponse2.statusCode, is(400))
        assertThat("Correct Content-Type", redirectionResponse2.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", redirectionResponse2.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat('Correct message', redirectionResponse2.jsonPath().getString("message"), is(MESSAGE_INCORRECT_REQUEST))
    }

    @Feature("EIDAS_AUTH_CALLBACK_ENDPOINT")
    def "Authentication with eIDAS. Callback with multiple param values #label"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.sessionId, COUNTRY_CA, [:])

        flow.setNextEndpoint(initEidasAuthenticationSession.htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA_HIGH)
        Response response = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        String endpointUrl = response.htmlPath().get("**.find {it.@method == 'post'}.@action")
        String samlResponse = response.htmlPath().get("**.find {it.@name == 'SAMLResponse'}.@value")
        String relayState = response.htmlPath().get("**.find {it.@name == 'RelayState'}.@value")

        Map paramsMap = ["SAMLResponse": samlResponse,
                         "RelayState"  : relayState]
        Map additionalParamsMap = [:]
        Utils.setParameter(additionalParamsMap, paramName, paramValue)

        when:
        Response redirectionResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap, additionalParamsMap)

        then:
        assertThat("Correct HTTP status code", redirectionResponse.statusCode, is(400))
        assertThat("Correct Content-Type", redirectionResponse.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", redirectionResponse.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", redirectionResponse.jsonPath().getString("message"), is(MESSAGE_DUPLICATE_PARAMETERS))
        assertThat("Correct path", redirectionResponse.jsonPath().getString('path'), is(flow.loginService.eidasCallbackUrl))

        where:
        paramName      | paramValue                                                                          || label
        "RelayState"   | "1XyyAocKwZp8Zp8qd9lhVKiJPF1AywyfpXTLqYGLFE73CKcEgSKOrfVq9UMfX9HAfWwBJMI9O7Bm22BZ1" || "relayState twice"
        "SAMLResponse" | "1XyyAocKwZp8Zp8qd9lhVKiJPF1AywyfpXTLqYGLFE73CKcEgSKOrfVq9UMfX9HAfWwBJMI9O7Bm22BZ1" || "SAMLResponse twice"
    }

    @Feature("EIDAS_AUTH_CALLBACK_ENDPOINT")
    def "Authentication with eIDAS. Callback with missing params #label"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.sessionId, COUNTRY_CA, [:])

        flow.setNextEndpoint(initEidasAuthenticationSession.htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA_HIGH)
        Response response = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        String endpointUrl = response.htmlPath().get("**.find {it.@method == 'post'}.@action")
        String samlResponse = response.htmlPath().get("**.find {it.@name == 'SAMLResponse'}.@value")
        String relayState = response.htmlPath().get("**.find {it.@name == 'RelayState'}.@value")

        Map paramsMap = [:]
        Utils.setParameter(paramsMap, paramName1, samlResponse)
        Utils.setParameter(paramsMap, paramName2, relayState)

        when:
        Response redirectionResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap, [:])

        then:
        assertThat("Correct HTTP status code", redirectionResponse.statusCode, is(400))
        assertThat("Correct Content-Type", redirectionResponse.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", redirectionResponse.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", redirectionResponse.jsonPath().getString("message"), is(errorMessage))
        assertThat("Correct path", redirectionResponse.jsonPath().getString('path'), is(flow.loginService.eidasCallbackUrl))

        where:
        paramName1     | paramName2   || label          || errorMessage
        "SAMLResponse" | _            || "RelayState"   || "Required request parameter 'RelayState' for method parameter type String is not present"
        _              | "RelayState" || "SAMLResponse" || "Required request parameter 'SAMLResponse' for method parameter type String is not present"
    }

    @Feature("EIDAS_AUTH_CALLBACK_ENDPOINT")
    def "Authentication with eIDAS. Invalid password"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.sessionId, COUNTRY_CA, [:])

        flow.setNextEndpoint(initEidasAuthenticationSession.htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response authorizationResponse = EidasSteps.continueEidasFlow(flow, IDP_USERNAME, "myPassword", EIDASLOA_HIGH)
        String endpointUrl = authorizationResponse.htmlPath().getString("**.find { it.@id == 'redirectForm' }.@action")
        String token = authorizationResponse.htmlPath().getString("**.find { it.@id == 'token' }.@value")
        Response eidasProxyResponse2 = EidasSteps.eidasProxyServiceRequest(flow, endpointUrl, token)
        Response colleagueResponse = EidasSteps.eidasColleagueResponse(flow, eidasProxyResponse2)
        Response authorizationResponse2 = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)

        when:
        Response redirectionResponse = EidasSteps.eidasRedirectAuthorizationResponse(flow, authorizationResponse2, false)

        then:
        assertThat("Correct HTTP status code", redirectionResponse.statusCode, is(400))
        assertThat("Correct Content-Type", redirectionResponse.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", redirectionResponse.jsonPath().getString("message"), is("eIDAS autentimine ebaõnnestus."))
    }

    @Feature("EIDAS_AUTH_CALLBACK_ENDPOINT")
    def "Authentication with eIDAS. Callback with invalid #label"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, flow.sessionId, COUNTRY_CA, [:])

        flow.setNextEndpoint(initEidasAuthenticationSession.htmlPath().getString("**.find { form -> form.@method == 'post' }.@action"))
        flow.setRelayState(initEidasAuthenticationSession.htmlPath().getString("**.find { input -> input.@name == 'RelayState' }.@value"))
        flow.setRequestMessage(initEidasAuthenticationSession.htmlPath().getString("**.find { input -> input.@name == 'SAMLRequest' }.@value"))
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA_HIGH)
        Response response = EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
        String endpointUrl = response.htmlPath().get("**.find {it.@method == 'post'}.@action")
        String samlResponse = response.htmlPath().get("**.find {it.@name == 'SAMLResponse'}.@value")
        String relayState = response.htmlPath().get("**.find {it.@name == 'RelayState'}.@value")

        Map paramsMap = [:]
        if (samlResponseValue == "default") {
            Utils.setParameter(paramsMap, "SAMLResponse", samlResponse)
        } else {
            Utils.setParameter(paramsMap, "SAMLResponse", samlResponseValue)
        }

        if (relayStateValue == "default") {
            Utils.setParameter(paramsMap, "RelayState", relayState)
        } else {
            Utils.setParameter(paramsMap, "RelayState", relayStateValue)
        }

        when:
        Response redirectionResponse = Requests.postRequestWithParams(flow, endpointUrl, paramsMap, [:])

        then:
        assertThat("Correct HTTP status code", redirectionResponse.statusCode, is(statusCode))
        assertThat("Correct Content-Type", redirectionResponse.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", redirectionResponse.jsonPath().getString("error"), is(error))
        assertThat("Correct message", redirectionResponse.jsonPath().getString("message"), is(errorMessage))

        where:
        samlResponseValue                           | relayStateValue || statusCode | error             | label                      | errorMessage
        "AB-"                                       | "default"       || 502        | "Bad Gateway"     | "SAMLResponse short value" | "eIDAS teenuses esinevad tehnilised tõrked. Palun proovige mõne aja pärast uuesti."
        RandomStringUtils.random(11000, true, true) | "default"       || 502        | "Bad Gateway"     | "SAMLResponse long value"  | "eIDAS teenuses esinevad tehnilised tõrked. Palun proovige mõne aja pärast uuesti."
        "default"                                   | "DC@"           || 400        | ERROR_BAD_REQUEST | "RelayState short value"   | MESSAGE_INCORRECT_REQUEST

    }
}
