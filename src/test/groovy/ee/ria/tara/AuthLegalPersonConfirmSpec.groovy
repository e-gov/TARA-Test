package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.commons.lang.RandomStringUtils
import org.hamcrest.Matchers
import spock.lang.Ignore
import spock.lang.IgnoreIf
import spock.lang.Unroll

import static org.hamcrest.Matchers.equalTo
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat
import static org.junit.Assert.assertTrue

@IgnoreIf({ properties['test.deployment.env'] != "idp" })
class AuthLegalPersonConfirmSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Unroll
    @Feature("LEGAL_PERSON_SELECTION_ENDPOINT")
    @Feature("UI_CONSENT_VIEW")
    @Feature("OIDC_ID_TOKEN")
    def "legal person selection request"() {
        expect:
        Response initClientAuthenticationSession = Steps.startAuthenticationInTara(flow, "openid legalperson")
        Response initLegalPersonResponse = Steps.authInitAsLegalPerson(flow, "60001019906", "00000766")
        Response legalPersonsResponse = Steps.loadLegalPersonsList(flow)
        String legalPersonIdentifier = legalPersonsResponse.body().jsonPath().get("legalPersons[0].legalPersonIdentifier").toString()
        String legalName = legalPersonsResponse.body().jsonPath().get("legalPersons[0].legalName").toString()

        Response response = Steps.selectLegalPersonAndConfirmIt(flow, legalPersonIdentifier)
        Response authenticationFinishedResponse = Steps.submitConsentAndFollowRedirects(flow, true, response)
        Response tokenResponse = Steps.getIdentityTokenResponse(flow, authenticationFinishedResponse)

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, tokenResponse.getBody().jsonPath().get("id_token")).getJWTClaimsSet()
        assertThat(claims.getAudience().get(0), equalTo(flow.oidcClient.clientId))
        assertThat(claims.getSubject(), equalTo("EE60001019906"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("given_name"), equalTo("MARY ÄNN"))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("represents_legal_person").getAt("registry_code"), equalTo(legalPersonIdentifier))
        assertThat(claims.getJSONObjectClaim("profile_attributes").get("represents_legal_person").getAt("name"), equalTo(legalName))
    }

    @Unroll
    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Verify legal person response headers"() {
        expect:
        Response initClientAuthenticationSession = Steps.startAuthenticationInTara(flow, "openid legalperson")
        Response initLegalPersonResponse = Steps.authInitAsLegalPerson(flow, "60001019906", "00000766")
        Response legalPersonsResponse = Steps.loadLegalPersonsList(flow)
        String legalPersonIdentifier = legalPersonsResponse.body().jsonPath().get("legalPersons[0].legalPersonIdentifier").toString()
        String legalName = legalPersonsResponse.body().jsonPath().get("legalPersons[0].legalName").toString()
        Response response = Steps.selectLegalPerson(flow, legalPersonIdentifier)
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        Steps.verifyResponseHeaders(response)
    }

    @Ignore // TARA2-75 , TARA2-165
    @Unroll
    @Feature("LEGAL_PERSON_SELECTION_ENDPOINT")
    def "legal person selection request with unsupported method get"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "legal_person_identifier", "123456789")
        Response response = Requests.getRequestWithParams(flow, flow.loginService.fullAuthLegalConfirmUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("Request method 'GET' not supported"))
    }

    @Unroll
    @Feature("LEGAL_PERSON_SELECTION_ENDPOINT")
    def "legal person selection request with no session and invalid parameter value"() {
        expect:
        Response initClientAuthenticationSession = Steps.startAuthenticationInTara(flow, "openid legalperson")
        Response initLegalPersonResponse = Steps.authInitAsLegalPerson(flow, "60001019906", "00000766")
        Response legalPersonsResponse = Steps.loadLegalPersonsList(flow)

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "legal_person_identifier", "123456789")
        def map3 = Utils.setParameter(paramsMap, "_csrf", flow.csrf)
        Response response = Requests.postRequestWithParams(flow, flow.loginService.fullAuthLegalConfirmUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 403, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertThat(response.body().jsonPath().get("error").toString(), equalTo("Forbidden"))
        String message = "Keelatud päring. Päring esitati topelt, sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."
        assertThat(response.body().jsonPath().get("message").toString(), equalTo(message))
    }

    @Unroll
    @Feature("LEGAL_PERSON_SELECTION_ENDPOINT")
    def "legal person selection request with invalid parameter value: #label"() {
        expect:
        Response initClientAuthenticationSession = Steps.startAuthenticationInTara(flow, "openid legalperson")
        Response initLegalPersonResponse = Steps.authInitAsLegalPerson(flow, "60001019906", "00000766")
        Response legalPersonsResponse = Steps.loadLegalPersonsList(flow)

        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "legal_person_identifier", legalPersonIdentifier)
        def map3 = Utils.setParameter(paramsMap, "_csrf", flow.csrf)
        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(cookiesMap, "SESSION", flow.sessionId)
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullAuthLegalConfirmUrl, cookiesMap, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", statusCode, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo(errorMessage))

        where:
        legalPersonIdentifier                    | label                                            || statusCode || errorMessage
        "123456789"                              | "invalid legal person identifier"                || 400        || "Antud id-ga juriidilist isikut ei leitud."
        RandomStringUtils.random(51, true, true) | "legal person identifier is too long"            || 400        || "confirmLegalPerson.legalPersonIdentifier: size must be between 0 and 50"
        "678@123"                                | "unsupported symbols in legal person identifier" || 400        || "confirmLegalPerson.legalPersonIdentifier: invalid legal person identifier"
        RandomStringUtils.random(50, true, true) | "legal person identifier max length"             || 400        || "Antud id-ga juriidilist isikut ei leitud."
    }

    @Unroll
    @Feature("LEGAL_PERSON_SELECTION_ENDPOINT")
    def "legal person selection request with multiple legal_person_identifier values"() {
        expect:
        Response initClientAuthenticationSession = Steps.startAuthenticationInTara(flow, "openid legalperson")
        Response initLegalPersonResponse = Steps.authInitAsLegalPerson(flow, "60001019906", "00000766")
        Response legalPersonsResponse = Steps.loadLegalPersonsList(flow)

        HashMap<String, String> cookiesMap = (HashMap)Collections.emptyMap()
        def map2 = Utils.setParameter(cookiesMap, "SESSION", flow.sessionId)
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "legal_person_identifier", "12597552")
        def map3 = Utils.setParameter(paramsMap, "_csrf", flow.csrf)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        def map4 = Utils.setParameter(additionalParamsMap, "legal_person_identifier", "10910878")
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullAuthLegalConfirmUrl, cookiesMap, paramsMap, additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        String message = "Multiple request parameters with the same name not allowed"
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo(message))
        assertTrue(response.body().jsonPath().get("incident_nr").toString().size() > 15)
    }

}
