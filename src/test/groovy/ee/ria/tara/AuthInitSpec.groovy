package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.commons.lang.RandomStringUtils
import org.hamcrest.Matchers
import org.spockframework.lang.Wildcard
import spock.lang.Unroll

import io.restassured.path.xml.XmlPath
import io.restassured.path.xml.XmlPath.CompatibilityMode

import static org.junit.jupiter.api.Assertions.*
import static org.hamcrest.MatcherAssert.assertThat


class AuthInitSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("AUTH_INIT_ENDPOINT")
    def "request initialize authentication"() {
        expect:
        Response initOIDCServiceSession = Steps.startAuthenticationInOidc(flow)
        assertEquals(302, initOIDCServiceSession.statusCode(), "Correct HTTP status code is returned")
        Response response = Steps.createLoginSession(flow, initOIDCServiceSession)
        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", response.getContentType(), "Correct content type")
        String sessionCookie = response.getCookie("SESSION")
        String sessionHeader = response.getHeader("Set-Cookie")
        assertEquals("SESSION=${sessionCookie}; Path=/; Secure; HttpOnly; SameSite=Strict".toString(), sessionHeader, "Correct header attribute Set-Cookie")
        assertEquals("et", response.getHeader("Content-Language"), "Correct header attribute Content-Language")
        XmlPath xmlPath = new XmlPath(CompatibilityMode.HTML, response.body().toString())
        int count = response.body().htmlPath().getInt("**.find { a -> a.text() == 'Tagasi teenusepakkuja juurde' }.size()")
        assertTrue(count > 0, "Link in estoninan exists")
    }

    @Unroll
    @Feature("AUTH_INIT_ENDPOINT")
    def "request initialize authentication language"() {
        expect:
        Map<String, String> paramsMap = OpenIdUtils.getAuthorizationParameters(flow, "openid", "et")
        Response initOIDCServiceSession = Steps.startAuthenticationInOidcWithParams(flow, paramsMap)

        assertEquals(302, initOIDCServiceSession.statusCode(), "Correct HTTP status code is returned")
        Response response = Steps.createLoginSession(flow, initOIDCServiceSession)
        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", response.getContentType(), "Correct content type")
        String sessionCookie = response.getCookie("SESSION")
        String sessionHeader = response.getHeader("Set-Cookie")
        assertEquals("SESSION=${sessionCookie}; Path=/; Secure; HttpOnly; SameSite=Strict".toString(), sessionHeader, "Correct header attribute Set-Cookie")
        assertEquals("et", response.getHeader("Content-Language"), "Correct header attribute Content-Language")
    }

    @Unroll
    @Feature("AUTH_INIT_ENDPOINT")
    def "initialize authentication session with: #label"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initOIDCServiceSession = Steps.startAuthenticationInOidc(flow)
        String loginChallenge = Utils.getParamValueFromResponseHeader(initOIDCServiceSession, "login_challenge")

        if (paramValue1 instanceof Wildcard) {
            def map1 = Utils.setParameter(paramsMap, paramName1, paramValue1)
        } else {
            def map1 = Utils.setParameter(paramsMap, paramName1, Utils.encodeUrl(paramValue1.toString()))
        }

        if (paramName2.equals("login_challenge") && paramValue2.equals("default")) {
            def map2 = Utils.setParameter(paramsMap, "login_challenge", loginChallenge)
        } else {
            def map2 = Utils.setParameter(paramsMap, paramName2, paramValue2)
        }
        Response initResponse = Requests.getRequestWithParams(flow, flow.loginService.fullInitUrl, paramsMap, additionalParamsMap)
        assertEquals(400, initResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat(initResponse.body().jsonPath().get("message"), Matchers.startsWith(errorMessage))

        where:
        paramName1        | paramValue1 | paramName2        | paramValue2 | label                                   || errorMessage
        "lang"            | "zu"        | "login_challenge" | "default"   | "invalid language code"                 || "authInit.language: supported values are: 'et', 'en', 'ru'"
        "login_challenge" | "12345"     | _                 | _           | "not existing login_challenge value"    || "Vigane päring. Päringu volituskood ei ole korrektne."
        _                 | _           | _                 | _           | "login_challenge param is missing"      || "Required request parameter 'login_challenge' for method parameter type String is not present"
        "login_challenge" | _           | _                 | _           | "empty login_challenge value"           || "authInit.loginChallenge: only characters and numbers allowed"
        "login_challenge" | "+372& (aa" | _                 | _           | "invalid symbols &( in login_challenge" || "authInit.loginChallenge: only characters and numbers allowed"
        _                 | _           | "login_challenge" | "+372"      | "invalid symbols + in login_challenge"  || "authInit.loginChallenge: only characters and numbers allowed"
        "login_challenge" | RandomStringUtils.random(51, true, true) | _ | _ | "too long login_challenge"           || "authInit.loginChallenge: size must be between 0 and 50"
    }

    @Unroll
    @Feature("AUTH_INIT_ENDPOINT")
    def "initialize authentication session with multiple parameters: #label"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initOIDCServiceSession = Steps.startAuthenticationInOidc(flow)
        String loginChallenge = Utils.getParamValueFromResponseHeader(initOIDCServiceSession, "login_challenge")
        def map1 = Utils.setParameter(paramsMap, "lang", "et")
        def map2 = Utils.setParameter(paramsMap, "login_challenge", loginChallenge)
        def map3 = Utils.setParameter(additionalParamsMap, paramName1, paramValue1)
        Response initResponse = Requests.getRequestWithParams(flow, flow.loginService.fullInitUrl, paramsMap, additionalParamsMap)
        assertEquals(400, initResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat(initResponse.body().jsonPath().get("message"), Matchers.startsWith(errorMessage))

        where:
        paramName1        | paramValue1 | paramName2 | paramValue2 | label             || errorMessage
        "lang"            | "zu"        | _          | _           | "language code"   || "Multiple request parameters with the same name not allowed"
        "login_challenge" | "12345"     | _          | _           | "login_challenge" || "Multiple request parameters with the same name not allowed"
    }

    @Unroll
    @Feature("AUTH_INIT_ENDPOINT")
    def "initialize authentication session ru"() {
        expect:
        LinkedHashMap<String, String> localeMap = (LinkedHashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(localeMap, "lang", "ru")
        Response initOIDCServiceSession = Steps.startAuthenticationInOidc(flow)
        Response response = Steps.initLoginSession(flow, initOIDCServiceSession, localeMap)
        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", response.getContentType(), "Correct content type")
        String sessionCookie = response.getCookie("SESSION")
        String sessionHeader = response.getHeader("Set-Cookie")
        assertEquals("SESSION=${sessionCookie}; Path=/; Secure; HttpOnly; SameSite=Strict".toString(), sessionHeader, "Correct header attribute Set-Cookie")
        assertEquals("ru", response.getHeader("Content-Language"), "Correct header attribute Content-Language")
        XmlPath xmlPath = new XmlPath(CompatibilityMode.HTML, response.body().toString())
        int count = response.body().htmlPath().getInt("**.find { a -> a.text() == 'Вернуться к поставщику услуг' }.size()")
        assertTrue(count > 0, "Link in Russian exists")
    }

    @Unroll
    @Feature("AUTH_INIT_ENDPOINT")
    def "initialize authentication session en"() {
        expect:
        LinkedHashMap<String, String> localeMap = (LinkedHashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(localeMap, "lang", "en")
        Response initOIDCServiceSession = Steps.startAuthenticationInOidc(flow)
        Response response = Steps.initLoginSession(flow, initOIDCServiceSession, localeMap)
        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", response.getContentType(), "Correct content type")
        String sessionCookie = response.getCookie("SESSION")
        String sessionHeader = response.getHeader("Set-Cookie")
        assertEquals("SESSION=${sessionCookie}; Path=/; Secure; HttpOnly; SameSite=Strict".toString(), sessionHeader, "Correct header attribute Set-Cookie")
        assertEquals("en", response.getHeader("Content-Language"), "Correct header attribute Content-Language")
        XmlPath xmlPath = new XmlPath(CompatibilityMode.HTML, response.body().toString())
        int count = response.body().htmlPath().getInt("**.find { a -> a.text() == 'Return to service provider' }.size()")
        assertTrue(count > 0, "Link in English exists")
    }
}
