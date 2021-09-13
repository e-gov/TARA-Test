package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.hamcrest.Matchers

import java.time.ZonedDateTime
import spock.lang.Unroll

import static org.junit.jupiter.api.Assertions.*
import static org.hamcrest.MatcherAssert.assertThat

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
        assertEquals(statusCode, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertEquals(errorMessage, response.body().jsonPath().get("message"), "Correct message text is returned")

        where:
        inputValue        || statusCode || errorMessage
        "invalid_client"  || 400        || "Kliendi autentimine ebaõnnestus. Tundmatu klient."
        "invalid_request" || 400        || "Kliendi autentimine ebaõnnestus (võimalikud põhjused: tundmatu klient, kliendi autentimist pole kaasatud, või toetamata autentimismeetod)"
        "service_error"   || 500        || "Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."
    }

    @Unroll
    @Feature("ERROR_CONTENT_JSON")
    def "Verify error response json"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(paramsMap, "error", "service_error")
        Response response = Requests.getRequestWithParams(flow, flow.loginService.fullErrorUrl, paramsMap, Collections.emptyMap())
        assertEquals(500, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        String errorText = "Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."
        assertEquals(errorText, response.body().jsonPath().get("message"), "Correct message text is returned")
        assertEquals("Internal Server Error", response.body().jsonPath().get("error"), "Correct error is returned")
        assertEquals(flow.loginService.errorUrl, response.body().jsonPath().get("path"), "Correct path is returned")
        assertEquals(500, response.body().jsonPath().getInt("status"), "Correct status is returned")
        def jsonTimestamp = ZonedDateTime.parse(response.body().jsonPath().get("timestamp"))
        def now = ZonedDateTime.now()
        def duration = now >> jsonTimestamp
        assertTrue(Math.abs(duration.seconds) < 10)

        assertThat("Supported locale", response.body().jsonPath().getString("locale"), Matchers.oneOf("et", "en", "ru"))
        assertTrue(response.body().jsonPath().getString("incident_nr").size() > 15)
    }

    @Unroll
    @Feature("USER_ERRORS")
    def "Verify error response html: general error"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "error", "service_error")
        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(headersMap, "Accept", "text/html")
        Response response = Requests.getRequestWithHeadersAndParams(flow, flow.loginService.fullErrorUrl, headersMap, paramsMap, Collections.emptyMap())
        assertEquals(500, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertTrue(response.body().htmlPath().getInt("**.find { strong -> strong.text() == 'Kasutaja tuvastamine ebaõnnestus.'}.size()") > 0)
        assertTrue(response.body().htmlPath().getInt("**.find { p -> p.text() == 'Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti.'}.size()") > 0)
        assertTrue(response.body().htmlPath().getString("**.find { it.@role == 'alert'}.p.text()").contains("Intsidendi number:"))
        assertTrue(response.body().htmlPath().getString("**.find { it.@role == 'alert'}.p.text()").contains("Edasta veakirjeldus"))
        assertTrue(response.body().htmlPath().getString("**.find { it.@role == 'alert'}.p.text()").contains("Palun saatke e-kiri aadressile"))
    }

    @Unroll
    @Feature("USER_ERRORS")
    def "Verify error response html: invalid client"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(paramsMap, "error", "invalid_client")
        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(headersMap, "Accept", "text/html")
        Response response = Requests.getRequestWithHeadersAndParams(flow, flow.loginService.fullErrorUrl, headersMap, paramsMap, Collections.emptyMap())
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertTrue(response.body().htmlPath().getInt("**.find { strong -> strong.text() == 'Kasutaja tuvastamine ebaõnnestus.'}.size()") > 0)
        assertTrue(response.body().htmlPath().getInt("**.find { p -> p.text() == 'Kliendi autentimine ebaõnnestus. Tundmatu klient.'}.size()") > 0)
        assertTrue(response.body().htmlPath().getString("**.find { it.@role == 'alert'}.p.text()").contains("Intsidendi number:"))
        assertTrue(response.body().htmlPath().getString("**.find { it.@role == 'alert'}.p.text()").contains("Edasta veakirjeldus"))
        assertTrue(response.body().htmlPath().getString("**.find { it.@role == 'alert'}.p.text()").contains("Palun saatke e-kiri aadressile"))
    }


}
