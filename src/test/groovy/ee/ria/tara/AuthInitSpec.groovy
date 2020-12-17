package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.commons.lang.RandomStringUtils
import org.hamcrest.Matchers
import org.spockframework.lang.Wildcard
import spock.lang.Unroll

import static org.junit.Assert.assertEquals
import io.restassured.path.xml.XmlPath
import io.restassured.path.xml.XmlPath.CompatibilityMode

import static org.junit.Assert.assertThat
import static org.junit.Assert.assertTrue

class AuthInitSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("AUTH_INIT_ENDPOINT")
    def "request initialize authentication"() {
        expect:
        Response initClientAuthenticationSession = Steps.createAuthenticationSession(flow)
        assertEquals("Correct HTTP status code is returned", 302, initClientAuthenticationSession.statusCode())
        Response initOIDCServiceSession = Steps.createOIDCSession(flow, initClientAuthenticationSession)
        assertEquals("Correct HTTP status code is returned", 302, initOIDCServiceSession.statusCode())
        Response response = Steps.createLoginSession(flow, initOIDCServiceSession)
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())
        assertEquals("Correct content type", "text/html;charset=UTF-8", response.getContentType())
        String sessionCookie = response.getCookie("SESSION")
        String sessionHeader = response.getHeader("Set-Cookie")
        assertEquals("Correct header attribute Set-Cookie", "SESSION=${sessionCookie}; Path=/; Secure; HttpOnly; SameSite=Strict".toString(), sessionHeader)
        assertEquals("Correct header attribute Content-Language", "et", response.getHeader("Content-Language"))
        XmlPath xmlPath = new XmlPath(CompatibilityMode.HTML, response.body().toString())
        int count = response.body().htmlPath().getInt("**.find { a -> a.text() == 'Tagasi teenusepakkuja juurde' }.size()")
        assertTrue("Link in Estonian exists", count > 0)
    }

    @Unroll
    @Feature("AUTH_INIT_ENDPOINT")
    def "request initialize authentication language"() {
        expect:
        // TODO followRedirectWithSessionId
        HashMap<String, String> cookiesMap = (HashMap) Collections.emptyMap()
        HashMap<String, String> paramMap = (HashMap) Collections.emptyMap()
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(paramMap, "TARAClient", "1234")
        Utils.setParameter(additionalParamsMap, "TARAClient", "1234")
        Requests.getRequestWithCookiesAndParams(flow, flow.oidcClient.fullRequestUrl
                , cookiesMap
                , paramMap
                , additionalParamsMap)
        Response initClientAuthenticationSession = Steps.createAuthenticationSession(flow)
        assertEquals("Correct HTTP status code is returned", 302, initClientAuthenticationSession.statusCode())
        Response initOIDCServiceSession = Steps.createOIDCSession(flow, initClientAuthenticationSession)
        assertEquals("Correct HTTP status code is returned", 302, initOIDCServiceSession.statusCode())
        Response response = Steps.createLoginSession(flow, initOIDCServiceSession)
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())
        assertEquals("Correct content type", "text/html;charset=UTF-8", response.getContentType())
        String sessionCookie = response.getCookie("SESSION")
        String sessionHeader = response.getHeader("Set-Cookie")
        assertEquals("Correct header attribute Set-Cookie", "SESSION=${sessionCookie}; Path=/; Secure; HttpOnly; SameSite=Strict".toString(), sessionHeader)
        assertEquals("Correct header attribute Content-Language", "et", response.getHeader("Content-Language"))
    }

    @Unroll
    @Feature("AUTH_INIT_ENDPOINT")
    def "initialize authentication session with: #label"() {
        expect:
        HashMap<String, String> paramsMap = (HashMap) Collections.emptyMap()
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initOIDCServiceSession = Steps.createSession(flow)
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
        assertEquals("Correct HTTP status code is returned", 400, initResponse.statusCode())
        assertThat(initResponse.body().jsonPath().get("message"), Matchers.startsWith(errorMessage))

        where:
        paramName1        | paramValue1 | paramName2        | paramValue2 | label                                || errorMessage
        "lang"            | "zu"        | "login_challenge" | "default"   | "invalid language code"              || "authInit.language: supported values are: 'et', 'en', 'ru'"
        "login_challenge" | "12345"     | _                 | _           | "invalid symbols in login_challenge" || " TODO"
        _                 | _           | _                 | _           | "login_challenge param is missing"   || "Required String parameter 'login_challenge' is not present"
        "login_challenge" | _           | _                 | _           | "empty login_challenge value"        || "authInit.loginChallenge: only characters and numbers allowed"
        "login_challenge" | "+372& (aa" | _                 | _           | "invalid symbols in login_challenge" || "authInit.loginChallenge: only characters and numbers allowed"
        _                 | _           | "login_challenge" | "+372"      | "invalid symbols in login_challenge" || "authInit.loginChallenge: only characters and numbers allowed"
        "login_challenge" | RandomStringUtils.random(51, true, true) | _ | _ | "too long login_challenge"        || "authInit.loginChallenge: size must be between 0 and 50"
    }

    @Unroll
    @Feature("AUTH_INIT_ENDPOINT")
    def "initialize authentication session ru"() {
        expect:
        LinkedHashMap<String, String> localeMap = (LinkedHashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(localeMap, "lang", "ru")
        Response initOIDCServiceSession = Steps.createSession(flow)
        Response response = Steps.initLoginSession(flow, initOIDCServiceSession, localeMap)
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())
        assertEquals("Correct content type", "text/html;charset=UTF-8", response.getContentType())
        String sessionCookie = response.getCookie("SESSION")
        String sessionHeader = response.getHeader("Set-Cookie")
        assertEquals("Correct header attribute Set-Cookie", "SESSION=${sessionCookie}; Path=/; Secure; HttpOnly; SameSite=Strict".toString(), sessionHeader)
        assertEquals("Correct header attribute Content-Language", "ru", response.getHeader("Content-Language"))
        XmlPath xmlPath = new XmlPath(CompatibilityMode.HTML, response.body().toString())
        int count = response.body().htmlPath().getInt("**.find { a -> a.text() == 'Вернуться к поставщику услуг' }.size()")
        assertTrue("Link in Russian exists", count > 0)
    }

    @Unroll
    @Feature("AUTH_INIT_ENDPOINT")
    def "initialize authentication session en"() {
        expect:
        LinkedHashMap<String, String> localeMap = (LinkedHashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(localeMap, "lang", "en")
        Response initOIDCServiceSession = Steps.createSession(flow)
        Response response = Steps.initLoginSession(flow, initOIDCServiceSession, localeMap)
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())
        assertEquals("Correct content type", "text/html;charset=UTF-8", response.getContentType())
        String sessionCookie = response.getCookie("SESSION")
        String sessionHeader = response.getHeader("Set-Cookie")
        assertEquals("Correct header attribute Set-Cookie", "SESSION=${sessionCookie}; Path=/; Secure; HttpOnly; SameSite=Strict".toString(), sessionHeader)
        assertEquals("Correct header attribute Content-Language", "en", response.getHeader("Content-Language"))
        XmlPath xmlPath = new XmlPath(CompatibilityMode.HTML, response.body().toString())
        int count = response.body().htmlPath().getInt("**.find { a -> a.text() == 'Return to service provider' }.size()")
        assertTrue("Link in Russian exists", count > 0)
    }
}
