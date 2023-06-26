package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.commons.lang3.RandomStringUtils
import org.hamcrest.Matchers

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.allOf
import static org.hamcrest.Matchers.is

class AuthInitSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Feature("AUTH_INIT_ENDPOINT")
    def "request initialize authentication"() {
        given:
        Response initOIDCServiceSession = Steps.startAuthenticationInOidc(flow)

        when:
        Response response = Steps.createLoginSession(flow, initOIDCServiceSession)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        assertThat("Correct Content-Type", response.contentType, is("text/html;charset=UTF-8"))
        assertThat("Correct cookie attributes", response.detailedCookie("SESSION").toString(), allOf(containsString("Secure"), containsString("HttpOnly"), containsString("Path=/"), containsString("SameSite=Strict")))
    }

    @Feature("AUTH_INIT_ENDPOINT")
    def "request initialize authentication language: #requestLocale"() {
        given:
        Map paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "openid", requestLocale)
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)

        when:
        Response response = Steps.createLoginSession(flow, initOIDCServiceSession)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        assertThat("Correct language", response.header("Content-Language"), is(responseLocale))
        assertThat("Correct title", response.htmlPath().getString("html.head.title"), is(title))

        where:
        requestLocale || responseLocale | title
        "et"          || "et"           | "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        "en"          || "en"           | "State authentication service - Secure authentication for e-services"
        "ru"          || "ru"           | "Государственная услуга аутентификации - Для безопасной аутентификации в э-услугах"
        "fi"          || "et"           | "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
        ""            || "et"           | "Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"
    }

    @Feature("AUTH_INIT_ENDPOINT")
    def "initialize authentication session with: #label"() {
        given:
        Steps.startAuthenticationInOidc(flow)

        when: "Login init request with invalid parameters"
        Response initResponse = Requests.getRequestWithParams(flow, flow.loginService.fullInitUrl, paramsMap)

        then:
        assertThat("Correct HTTP status code", initResponse.statusCode, is(400))
        assertThat("Correct message", initResponse.jsonPath().getString("message"), Matchers.startsWith(errorMessage))

        where:
        paramsMap                                                   | label                                    || errorMessage
        [lang: "zu", login_challenge: "12345"]                      | "invalid language code"                  || "authInit.language: supported values are: 'et', 'en', 'ru'"
        [login_challenge: "12345"]                                  | "not existing login_challenge value"     || "Vigane päring. Päringu volituskood ei ole korrektne."
        [:]                                                         | "login_challenge param is missing"       || "Required request parameter 'login_challenge' for method parameter type String is not present"
        [login_challenge: null]                                     | "empty login_challenge value"            || "authInit.loginChallenge: only characters and numbers allowed"
        [login_challenge: "+372&+(aa"]                              | "invalid symbols &+( in login_challenge" || "authInit.loginChallenge: only characters and numbers allowed"
        [login_challenge: RandomStringUtils.random(51, true, true)] | "too long login_challenge"               || "authInit.loginChallenge: size must be between 0 and 50"
        [lang: ["et", "zu"], login_challenge: "12345"]              | "multiple language codes"                || MESSAGE_DUPLICATE_PARAMETERS
        [lang: "et", login_challenge: ["12345", "54321"]]           | "multiple login challenges"              || MESSAGE_DUPLICATE_PARAMETERS
    }
}
