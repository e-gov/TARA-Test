package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import java.time.Duration
import java.time.ZonedDateTime

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.lessThan

class ServiceErrorsSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Feature("FORWARDED_OIDC_ERRORS")
    def "Filter service errors for end user: #inputValue"() {
        given:
        Map paramsMap = ["error": inputValue]

        when:
        Response response = Requests.getRequestWithParams(flow, flow.loginService.fullErrorUrl, paramsMap, [:])

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
        given:
        Map paramsMap = ["error": ERROR_SERVICE]

        when:
        Response response = Requests.getRequestWithParams(flow, flow.loginService.fullErrorUrl, paramsMap, [:])

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
        given:
        Map paramsMap = ["error": ERROR_SERVICE]
        Map headersMap = ["Accept": "text/html"]

        when:
        Response response = Requests.getRequestWithHeadersAndParams(flow, flow.loginService.fullErrorUrl, headersMap, paramsMap, [:])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("text/html;charset=UTF-8"))
        assertThat(response.htmlPath().getString("*"), containsString("Kasutaja tuvastamine ebaõnnestus."))
        assertThat(response.htmlPath().getString("*"), containsString("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
        assertThat(response.htmlPath().getString("*"), containsString("Intsidendi number:"))
        assertThat(response.htmlPath().getString("*"), containsString("Edasta veakirjeldus"))
        assertThat(response.htmlPath().getString("*"), containsString("Palun saatke e-kiri aadressile"))
    }

    @Feature("USER_ERRORS")
    def "Verify error response html: invalid client"() {
        given:
        Map paramsMap = ["error": ERROR_CLIENT]
        Map headersMap = ["Accept": "text/html"]

        when:
        Response response = Requests.getRequestWithHeadersAndParams(flow, flow.loginService.fullErrorUrl, headersMap, paramsMap, [:])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("text/html;charset=UTF-8"))
        assertThat(response.htmlPath().getString("*"), containsString("Kasutaja tuvastamine ebaõnnestus."))
        assertThat(response.htmlPath().getString("*"), containsString("Kliendi autentimine ebaõnnestus. Tundmatu klient."))
        assertThat(response.htmlPath().getString("*"), containsString("Intsidendi number:"))
        assertThat(response.htmlPath().getString("*"), containsString("Edasta veakirjeldus"))
        assertThat(response.htmlPath().getString("*"), containsString("Palun saatke e-kiri aadressile"))
    }


}
