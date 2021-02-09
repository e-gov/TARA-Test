package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.hamcrest.Matchers

import java.time.ZonedDateTime
import spock.lang.Unroll

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat
import static org.junit.Assert.assertTrue

class ServiceErrorsSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("FORWARDED_OIDC_ERRORS")
    def "Filter service errors for end user: #inputValue"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(paramsMap, "error", inputValue)
        Response response = Requests.getRequestWithParams(flow, flow.loginService.fullErrorUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", statusCode, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        assertEquals("Correct message text is returned", errorMessage, response.body().jsonPath().get("message"))

        where:
        inputValue        || statusCode || errorMessage
        "invalid_client"  || 400        || "Kliendi autentimine ebaõnnestus. Tundmatu klient."
        "invalid_request" || 400        || "Kliendi autentimine ebaõnnestus (võimalikud põhjused: tundmatu klient, kliendi autentimist pole kaasatud, või toetamata autentimismeetod)"
        "service_error"   || 500        || "Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."
    }

    @Unroll
    @Feature("ERROR_CONTENT_JSON")
    def "Verify error response"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(paramsMap, "error", "service_error")
        Response response = Requests.getRequestWithParams(flow, flow.loginService.fullErrorUrl, paramsMap, Collections.emptyMap())
        assertEquals("Correct HTTP status code is returned", 500, response.statusCode())
        assertEquals("Correct Content-Type is returned", "application/json;charset=UTF-8", response.getContentType())
        String errorText = "Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."
        assertEquals("Correct message text is returned", errorText, response.body().jsonPath().get("message"))
        assertEquals("Correct error is returned", "Internal Server Error", response.body().jsonPath().get("error"))
        assertEquals("Correct path is returned", flow.loginService.errorUrl, response.body().jsonPath().get("path"))
        assertEquals("Correct status is returned", 500, response.body().jsonPath().getInt("status"))
        def jsonTimestamp = ZonedDateTime.parse(response.body().jsonPath().get("timestamp"))
        def now = ZonedDateTime.now()
        def duration = now >> jsonTimestamp
        assertTrue(Math.abs(duration.seconds) < 10)

        assertThat("Supported locale", response.body().jsonPath().getString("locale"), Matchers.oneOf("et", "en", "ru"))
        assertTrue(response.body().jsonPath().getString("incident_nr").size() > 15)
    }


}
