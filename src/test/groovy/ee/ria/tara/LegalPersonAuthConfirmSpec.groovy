package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.commons.lang3.RandomStringUtils

import static io.restassured.RestAssured.given
import static org.hamcrest.MatcherAssert.assertThat
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
    def "Legal person selection request should succeed"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.authInitAsLegalPerson(flow)
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
    def "Verify legal person response headers should succeed"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.authInitAsLegalPerson(flow)
        Response legalPersonsResponse = Steps.loadLegalPersonsList(flow)
        String legalPersonIdentifier = legalPersonsResponse.jsonPath().getString("legalPersons[0].legalPersonIdentifier")

        when:
        Response response = Steps.selectLegalPerson(flow, legalPersonIdentifier)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(302))
        Steps.verifyResponseHeaders(response)
    }

    //TODO: AUT-630
    @Feature("LEGAL_PERSON_SELECTION_ENDPOINT")
    def "Legal person selection request with unsupported method should fail: #requestType "() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.authInitAsLegalPerson(flow)
        Response legalPersonsResponse = Steps.loadLegalPersonsList(flow)
        String legalPersonIdentifier = legalPersonsResponse.jsonPath().getString("legalPersons[0].legalPersonIdentifier")

        when: "Legal person selection request with unsupported method"
        Response response = given()
                .relaxedHTTPSValidation()
                .cookies([SESSION: flow.sessionId])
                .params([legal_person_identifier: legalPersonIdentifier,
                         _csrf                  : flow.csrf])
                .request(requestType, flow.loginService.fullAuthLegalConfirmUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_INTERNAL_ERROR))

        where:
        requestType | _
        "GET"       | _
        "PUT"       | _
        "PATCH"     | _
        "DELETE"    | _
    }

    @Feature("LEGAL_PERSON_SELECTION_ENDPOINT")
    def "Legal person selection request with invalid session cookie should fail: #reason"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.authInitAsLegalPerson(flow)
        Steps.loadLegalPersonsList(flow)

        when: "legal person selection request with invalid session cookie"
        Response response = given()
                .relaxedHTTPSValidation()
                .cookies(cookie)
                .params([legal_person_identifier: "123456789",
                         _csrf                  : flow.csrf])
                .post(flow.loginService.fullAuthLegalConfirmUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(403))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_FORBIDDEN))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_FORBIDDEN_REQUEST))

        where:
        cookie               | reason
        [:]                  | "no cookie"
        [SESSION: null]      | "empty cookie"
        [SESSION: "1234567"] | "incorrect cookie value"
    }

    @Feature("LEGAL_PERSON_SELECTION_ENDPOINT")
    def "Legal person selection request with invalid parameter value should fail: #label"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.authInitAsLegalPerson(flow)
        Steps.loadLegalPersonsList(flow)

        when: "legal person selection request with invalid legal person identifier"
        Response response = Requests.postRequestWithParams(flow, flow.loginService.fullAuthLegalConfirmUrl, [legal_person_identifier: legalPersonIdentifier, _csrf: flow.csrf])

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
        ["12597552", "10910878"]                 | "multiple legal person identifiers"              || MESSAGE_DUPLICATE_PARAMETERS
    }
}
