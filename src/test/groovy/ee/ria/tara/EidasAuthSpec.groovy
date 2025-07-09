package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.qameta.allure.Step
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.commons.lang3.RandomStringUtils

import static io.restassured.RestAssured.given
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.greaterThan
import static org.hamcrest.Matchers.hasLength
import static org.hamcrest.Matchers.is

class EidasAuthSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Feature("EIDAS_AUTH_INIT_ENDPOINT")
    def "Initialize eIDAS authentication should succeed"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid eidas")

        when:
        Response initEidasAuthenticationSession = EidasSteps.initEidasAuthSession(flow, COUNTRY_CA)

        then:
        assertThat("Correct HTTP status code", initEidasAuthenticationSession.statusCode, is(200))
        assertThat("Correct Content-Type", initEidasAuthenticationSession.contentType, is("text/html;charset=UTF-8"))
        String buttonLabel = initEidasAuthenticationSession.htmlPath().getString('**.find { input -> input.@type == \'submit\'}.@value')
        assertThat("Continue button exists", buttonLabel, is("Continue"))
    }

    @Feature("EIDAS_AUTH_INIT_ENDPOINT")
    @Feature("EIDAS_AUTH_INIT_REQUEST_CHECKS")
    def "Initialize eIDAS authentication should fail with #label"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid eidas")

        when:
        Response response = EidasSteps.initEidasAuthSession(flow, country)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString('message'), is("Antud riigikood ei ole lubatud. Lubatud riigikoodid on:<span translate=\"no\"> CA, DE</span>"))
        assertThat("Incident number is present", response.jsonPath().getString("incident_nr"), hasLength(32))

        where:
        country | label
        ""      | "missing country parameter"
        "bg"    | "country code is not in list"
        "BG"    | "capitalized country code is not in list"
        "ca"    | "country code must be capitalized"
        "F"     | "country code must be capitalized"
        "a1"    | "country code is not in list"
    }

    @Feature("EIDAS_AUTH_INIT_ENDPOINT")
    def "Initialize eIDAS authentication without session cookie should fail"() {
        when:
        Response response = Requests.postRequestWithParams(flow, flow.loginService.fullEidasInitUrl, [country: COUNTRY_CA])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(403))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString("message"), is(MESSAGE_FORBIDDEN_REQUEST))
    }

    //TODO: AUT-630
    @Feature("EIDAS_AUTH_INIT_ENDPOINT")
    def "Initialize eIDAS authentication with invalid method: requestType"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid eidas")

        when: "Initialize eIDAS authentication with invalid method"
        Response response = given()
                .cookies("__Host-SESSION": flow.sessionId)
                .params([country: COUNTRY_CA,
                         _csrf  : flow.csrf])
                .request(requestType, flow.loginService.fullEidasInitUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString("message"), is(MESSAGE_INTERNAL_ERROR))

        where:
        requestType | _
        "GET"       | _
        "PUT"       | _
        "PATCH"     | _
        "DELETE"    | _
    }

    @Feature("EIDAS_AUTH_INIT_ENDPOINT")
    def "Initialize eIDAS authentication with multiple parameters"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid eidas")

        when: "Initialize eIDAS authentication with duplicate parameter"
        Response response = Requests.postRequestWithParams(flow, flow.loginService.fullEidasInitUrl, [_csrf: flow.csrf, country: ["CA", "CA"]])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString("message"), is(MESSAGE_DUPLICATE_PARAMETERS))
    }

    @Feature("AUTH_INIT_WITH_EIDASONLY_AND_COUNTRY")
    def "Initialize eIDAS authentication with scope: #scope and redirect into CA eIDAS network"() {
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
    def "Initialize eIDAS authentication with eIDAS scope: #label"() {
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
        Response authorizationResponse = authenticateToEidasAuthorization(flow)
        EidasSteps.eidasRedirectAuthorizationResponse(flow, authorizationResponse)

        when: "Request eIDAS callback again with already used relay state"
        Response secondCallback = EidasSteps.eidasRedirectAuthorizationResponse(flow, authorizationResponse, false)

        then:
        assertThat("Correct HTTP status code", secondCallback.statusCode, is(400))
        assertThat("Correct Content-Type", secondCallback.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", secondCallback.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat('Correct message', secondCallback.jsonPath().getString("message"), is(MESSAGE_INCORRECT_REQUEST))
    }

    @Feature("EIDAS_AUTH_CALLBACK_ENDPOINT")
    def "Authentication with eIDAS. Callback with duplicate param values should fail: #label"() {
        given:
        authenticateToEidasAuthorization(flow)

        and: "Create valid parameter map"
        Map paramsMap = [SAMLResponse: flow.responseMessage,
                         RelayState  : flow.relayState]

        and: "Change parameter"
        paramsMap << parameters

        when: "Request eIDAS callback with duplicate parameters"
        Response redirectionResponse = Requests.postRequestWithParams(flow, flow.nextEndpoint, paramsMap)

        then:
        assertThat("Correct HTTP status code", redirectionResponse.statusCode, is(400))
        assertThat("Correct Content-Type", redirectionResponse.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", redirectionResponse.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", redirectionResponse.jsonPath().getString("message"), is(MESSAGE_DUPLICATE_PARAMETERS))
        assertThat("Correct path", redirectionResponse.jsonPath().getString('path'), is(flow.loginService.eidasCallbackUrl))

        where:
        parameters                           || label
        [RelayState: ["123abc", "abc123"]]   || "duplicate relayState"
        [SAMLResponse: ["123abc", "abc123"]] || "duplicate SAMLResponse"
    }

    @Feature("EIDAS_AUTH_CALLBACK_ENDPOINT")
    def "Authentication with eIDAS. Callback with missing parameter #paramName"() {
        given:
        authenticateToEidasAuthorization(flow)

        and: "Create valid parameter map"
        Map paramsMap = [SAMLResponse: flow.responseMessage,
                         RelayState  : flow.relayState]

        and: "Remove parameter"
        paramsMap.remove(paramName)

        when: "Request eIDAS callback with missing parameter"
        Response redirectionResponse = Requests.postRequestWithParams(flow, flow.nextEndpoint, paramsMap)

        then:
        assertThat("Correct HTTP status code", redirectionResponse.statusCode, is(400))
        assertThat("Correct Content-Type", redirectionResponse.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", redirectionResponse.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", redirectionResponse.jsonPath().getString("message"), is(errorMessage))
        assertThat("Correct path", redirectionResponse.jsonPath().getString('path'), is(flow.loginService.eidasCallbackUrl))

        where:
        paramName      || errorMessage
        "SAMLResponse" || "Required request parameter 'SAMLResponse' for method parameter type String is not present"
        "RelayState"   || "Required request parameter 'RelayState' for method parameter type String is not present"
    }

    @Feature("EIDAS_AUTH_CALLBACK_ENDPOINT")
    def "Authentication with eIDAS. Invalid password"() {
        given:
        Steps.startAuthenticationInTara(flow, "openid eidas")
        EidasSteps.initEidasAuthSession(flow, COUNTRY_CA)
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
        authenticateToEidasAuthorization(flow)

        and: "Create valid parameter map"
        Map paramsMap = [SAMLResponse: flow.responseMessage,
                         RelayState  : flow.relayState]

        and: "Change parameter"
        paramsMap << parameter

        when:
        Response redirectionResponse = Requests.postRequestWithParams(flow, flow.nextEndpoint, paramsMap)

        then:
        assertThat("Correct HTTP status code", redirectionResponse.statusCode, is(statusCode))
        assertThat("Correct Content-Type", redirectionResponse.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", redirectionResponse.jsonPath().getString("error"), is(error))
        assertThat("Correct message", redirectionResponse.jsonPath().getString("message"), is(errorMessage))

        where:
        parameter                                                   || statusCode | error             | label                      | errorMessage
        [SAMLResponse: "AB-"]                                       || 502        | "Bad Gateway"     | "SAMLResponse short value" | "eIDAS teenuses esinevad tehnilised tõrked. Palun proovige mõne aja pärast uuesti."
        [SAMLResponse: RandomStringUtils.random(11000, true, true)] || 502        | "Bad Gateway"     | "SAMLResponse long value"  | "eIDAS teenuses esinevad tehnilised tõrked. Palun proovige mõne aja pärast uuesti."
        [RelayState: "DC@"]                                         || 400        | ERROR_BAD_REQUEST | "RelayState short value"   | MESSAGE_INCORRECT_REQUEST
    }

    @Step("Authentication flow up to eIDAS authorization request")
    private static authenticateToEidasAuthorization(Flow flow) {
        Steps.startAuthenticationInTara(flow, "openid eidas")
        EidasSteps.initEidasAuthSession(flow, COUNTRY_CA)
        Response colleagueResponse = EidasSteps.continueEidasAuthenticationFlow(flow, IDP_USERNAME, IDP_PASSWORD, EIDASLOA_HIGH)
        EidasSteps.getAuthorizationResponseFromEidas(flow, colleagueResponse)
    }
}
