package ee.ria.tara

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

class ServiceErrorsSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Feature("FORWARDED_OIDC_ERRORS")
    def "Filter service errors for end user: #inputValue"() {
        when:
        Response response = Requests.getRequestWithParams(flow, flow.loginService.fullErrorUrl, ["error": inputValue])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(statusCode))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", response.jsonPath().getString("message"), is(errorMessage))

        where:
        inputValue    || statusCode | errorMessage
        ERROR_CLIENT  || 400        | "Kliendi autentimine ebaõnnestus. Tundmatu klient."
        ERROR_REQUEST || 400        | "Kliendi autentimine ebaõnnestus (võimalikud põhjused: tundmatu klient, kliendi autentimist pole kaasatud, või toetamata autentimismeetod)"
        ERROR_SERVICE || 500        | MESSAGE_INTERNAL_ERROR
    }

    @Feature("ERROR_CONTENT_JSON")
    def "Verify error response json"() {
        when:
        Response response = Requests.getRequestWithParams(flow, flow.loginService.fullErrorUrl, ["error": ERROR_SERVICE])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error message", response.jsonPath().getString("message"), is(MESSAGE_INTERNAL_ERROR))
        assertThat("Correct error", response.jsonPath().getString("error"), is("Internal Server Error"))
        assertThat("Correct path", response.jsonPath().getString("path"), is(flow.loginService.errorUrl))
        assertThat("Correct HTTP status code", response.jsonPath().getInt("status"), is(500))
        def jsonTimestamp = ZonedDateTime.parse(response.jsonPath().get("timestamp"))
        def now = ZonedDateTime.now()
        Duration duration = Duration.between(now, jsonTimestamp)
        def durationInSeconds = Math.abs(duration.toSeconds())
        assertThat("Correct timestamp", durationInSeconds.toInteger(), lessThan(10))
        assertThat("Supported locale", response.jsonPath().getString("locale"), is("et"))
        assertThat("Incident number is present", response.jsonPath().getString("incident_nr").size() > 15)
    }

    @Feature("USER_ERRORS")
    def "Verify error response html: general error"() {
        when:
        Response response = given()
                .params(["error": ERROR_SERVICE])
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
                .params(["error": ERROR_CLIENT])
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
