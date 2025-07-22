package ee.ria.tara

import ee.ria.tara.model.ErrorMessage
import ee.ria.tara.model.OidcError
import ee.ria.tara.util.ErrorValidator
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import java.time.Duration
import java.time.ZonedDateTime

import static io.restassured.RestAssured.given
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.lessThan
import static org.hamcrest.Matchers.greaterThan

class ServiceErrorsSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Feature("FORWARDED_OIDC_ERRORS")
    def "Filter service errors for end user: #inputValue"() {
        when:
        Response response = Requests.getRequestWithParams(flow, flow.loginService.fullErrorUrl, ["error": inputValue])

        then:
        ErrorValidator.validate(response, errorMessage)

        where:
        inputValue                     || errorMessage
        OidcError.INVALID_CLIENT.code  || ErrorMessage.INVALID_OIDC_CLIENT
        OidcError.INVALID_REQUEST.code || ErrorMessage.INVALID_OIDC_REQUEST
        OidcError.SERVICE_ERROR.code   || ErrorMessage.INTERNAL_ERROR
    }

    @Feature("ERROR_CONTENT_JSON")
    def "Verify error response json"() {
        when:
        Response response = Requests.getRequestWithParams(flow, flow.loginService.fullErrorUrl, ["error": OidcError.SERVICE_ERROR.code])

        then:
        ErrorValidator.validate(response, ErrorMessage.INTERNAL_ERROR)

        response.then().body(
                "path", is(flow.loginService.errorUrl),
                "status", is(500),
                "locale", is("et"),
                "incident_nr.size()", greaterThan(15)
        )

        long timestampAge = Duration.between(
                ZonedDateTime.parse(response.jsonPath().get("timestamp")),
                ZonedDateTime.now()
        ).abs().seconds
        assertThat("Timestamp should be within 10 seconds", timestampAge, lessThan(10L))
    }

    @Feature("USER_ERRORS")
    def "Verify error response html: general error"() {
        when:
        Response response = given()
                .params(["error": OidcError.SERVICE_ERROR.code])
                .headers(["Accept": "text/html"])
                .get(flow.loginService.fullErrorUrl)

        String htmlResponse = response.body.asString()

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("text/html;charset=UTF-8"))
        assertThat(htmlResponse, containsString("Kasutaja tuvastamine ebaõnnestus."))
        assertThat(htmlResponse, containsString("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
        assertThat(htmlResponse, containsString("Intsidendi number:"))
        assertThat(htmlResponse, containsString("Edasta veakirjeldus"))
        assertThat(htmlResponse, containsString("Palun saatke e-kiri aadressile"))
    }

    @Feature("USER_ERRORS")
    def "Verify error response html: invalid client"() {
        when:
        Response response = given()
                .params(["error": OidcError.INVALID_CLIENT.code])
                .headers(["Accept": "text/html"])
                .get(flow.loginService.fullErrorUrl)

        String htmlResponse = response.body.asString()

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("text/html;charset=UTF-8"))
        assertThat(htmlResponse, containsString("Kasutaja tuvastamine ebaõnnestus."))
        assertThat(htmlResponse, containsString("Kliendi autentimine ebaõnnestus. Tundmatu klient."))
        assertThat(htmlResponse, containsString("Intsidendi number:"))
        assertThat(htmlResponse, containsString("Edasta veakirjeldus"))
        assertThat(htmlResponse, containsString("Palun saatke e-kiri aadressile"))
    }


}
