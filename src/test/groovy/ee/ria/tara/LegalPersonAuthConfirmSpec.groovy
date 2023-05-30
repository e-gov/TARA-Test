package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.commons.lang3.RandomStringUtils

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.hasLength
import static org.hamcrest.Matchers.is

class LegalPersonAuthConfirmSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Feature("LEGAL_PERSON_SELECTION_ENDPOINT")
    @Feature("UI_CONSENT_VIEW")
    @Feature("OIDC_ID_TOKEN")
    def "legal person selection request"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.authInitAsLegalPerson(flow, "60001019906", "00000766")
        Response legalPersonsResponse = Steps.loadLegalPersonsList(flow)
        String legalPersonIdentifier = legalPersonsResponse.jsonPath().getString("legalPersons[0].legalPersonIdentifier")
        String legalName = legalPersonsResponse.jsonPath().getString("legalPersons[0].legalName")

        Response response = Steps.selectLegalPersonAndConfirmIt(flow, legalPersonIdentifier)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, response)

        when:
        Response tokenResponse = Steps.getIdentityTokenResponseWithClient(flow, authenticationFinishedResponse, flow.oidcClientLegal.fullResponseUrl, flow.oidcClientLegal.clientId, flow.oidcClientLegal.clientSecret)
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.jsonPath().get("id_token")).JWTClaimsSet

        then:
        assertThat("Correct audience", claims.audience[0], is(flow.oidcClientLegal.clientId))
        assertThat("Correct subject", claims.subject, is("EE60001019906"))
        assertThat("Correct given name", claims.getJSONObjectClaim("profile_attributes")["given_name"], is("MARY ÄNN"))
        assertThat("Correct registry code", claims.getJSONObjectClaim("profile_attributes")["represents_legal_person"]["registry_code"], is(legalPersonIdentifier))
        assertThat("Correct legal name", claims.getJSONObjectClaim("profile_attributes")["represents_legal_person"]["name"], is(legalName))
    }

    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Verify legal person response headers"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.authInitAsLegalPerson(flow, "60001019906", "00000766")
        Response legalPersonsResponse = Steps.loadLegalPersonsList(flow)
        String legalPersonIdentifier = legalPersonsResponse.jsonPath().get("legalPersons[0].legalPersonIdentifier").toString()

        when:
        Response response = Steps.selectLegalPerson(flow, legalPersonIdentifier)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(302))
        Steps.verifyResponseHeaders(response)
    }

    //TODO: AUT-630
    @Feature("LEGAL_PERSON_SELECTION_ENDPOINT")
    def "legal person selection request with unsupported method get"() {
        given:
        Map paramsMap = ["legal_person_identifier": "123456789"]

        when:
        Response response = Requests.getRequestWithParams(flow, flow.loginService.fullAuthLegalConfirmUrl, paramsMap, [:])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_INTERNAL_ERROR))
    }

    @Feature("LEGAL_PERSON_SELECTION_ENDPOINT")
    def "legal person selection request with no session and invalid parameter value"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.authInitAsLegalPerson(flow, "60001019906", "00000766")
        Steps.loadLegalPersonsList(flow)

        Map paramsMap = ["legal_person_identifier": "123456789",
                         "_csrf"                  : flow.csrf]

        when:
        Response response = Requests.postRequestWithParams(flow, flow.loginService.fullAuthLegalConfirmUrl, paramsMap, [:])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(403))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_FORBIDDEN))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_FORBIDDEN_REQUEST))
    }

    @Feature("LEGAL_PERSON_SELECTION_ENDPOINT")
    def "legal person selection request with invalid parameter value: #label"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.authInitAsLegalPerson(flow, "60001019906", "00000766")
        Steps.loadLegalPersonsList(flow)

        Map cookiesMap = ["SESSION": flow.sessionId]
        Map paramsMap = ["legal_person_identifier": legalPersonIdentifier,
                         "_csrf"                  : flow.csrf]

        when:
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullAuthLegalConfirmUrl, cookiesMap, paramsMap, [:])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString("message"), is(errorMessage))

        where:
        legalPersonIdentifier                    | label                                            || errorMessage
        "123456789"                              | "invalid legal person identifier"                || "Antud identifikaatoriga juriidilist isikut ei leitud."
        RandomStringUtils.random(51, true, true) | "legal person identifier is too long"            || "confirmLegalPerson.legalPersonIdentifier: size must be between 0 and 50"
        "678@123"                                | "unsupported symbols in legal person identifier" || "confirmLegalPerson.legalPersonIdentifier: invalid legal person identifier"
        RandomStringUtils.random(50, true, true) | "legal person identifier max length"             || "Antud identifikaatoriga juriidilist isikut ei leitud."
    }

    @Feature("LEGAL_PERSON_SELECTION_ENDPOINT")
    def "legal person selection request with multiple legal_person_identifier values"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.authInitAsLegalPerson(flow, "60001019906", "00000766")
        Steps.loadLegalPersonsList(flow)

        Map cookiesMap = ["SESSION": flow.sessionId]
        Map paramsMap = ["legal_person_identifier": "12597552",
                         "_csrf"                  : flow.csrf]
        Map additionalParamsMap = ["legal_person_identifier": "10910878"]

        when:
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullAuthLegalConfirmUrl, cookiesMap, paramsMap, additionalParamsMap)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString('message'), is(MESSAGE_DUPLICATE_PARAMETERS))
        assertThat("Incident number is present", response.jsonPath().getString("incident_nr"), hasLength(32))
    }
}
