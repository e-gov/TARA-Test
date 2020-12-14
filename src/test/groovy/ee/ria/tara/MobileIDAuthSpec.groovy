package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Unroll
import org.hamcrest.Matchers

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat

class MobileIDAuthSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("MID_INIT_ENDPOINT")
    def "initialize mobile-ID authentication"() {
        expect:
        Steps.initAuthenticationSession(flow)
        HashMap<String, String> additionalParamsMap = (HashMap) Collections.emptyMap()
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017716", "69100366", additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        assertEquals("Correct Content-Type is returned", "text/html;charset=UTF-8", initMidAuthenticationSession.getContentType())
        String controlCode = initMidAuthenticationSession.body().htmlPath().getString("**.find { p -> p.@class == 'control-code' }.text()")
        assertEquals("Verification code exists", 4, controlCode.size())
    }


    @Unroll
    @Feature("MID_AUTH_POLL_RESPONSE_COMPLETE")
    def "initialize mobile-ID authentication with scenario: #label et"() {
        expect:
        LinkedHashMap<String, String> additionalParamsMap = (LinkedHashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(additionalParamsMap, additionalParameterName, additionalParameterValue)
        Steps.initAuthenticationSession(flow)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, idCode, phoneNo, additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 400, pollResponse.statusCode())
        assertThat(pollResponse.body().jsonPath().get("message"), Matchers.startsWith(errorMessage))

        where:
        phoneNo    | idCode        | additionalParameterName | additionalParameterValue | label                                            || errorMessage
        "00000266" | "60001019939" | _                       | _                        | "Mobile-ID user has no active certificates"      || "Kasutajal pole Mobiil-ID lepingut."
        "07110066" | "60001019947" | _                       | _                        | "Sending authentication request to phone failed" || "Teie mobiiltelefoni ei saa Mobiil-ID autentimise sõnumeid saata."
        "01100266" | "60001019950" | _                       | _                        | "User cancelled authentication"                  || "Autentimine on katkestatud."
        "00000666" | "60001019961" | _                       | _                        | "Created signature is not valid"                 || "Autentimine Mobiil-ID-ga ei õnnestunud. Testi oma Mobiil-ID toimimist DigiDoc4 kliendis:"
        "01200266" | "60001019972" | _                       | _                        | "SIM application error"                          || "Teie mobiiltelefoni SIM kaardiga tekkis tõrge."
        "13100266" | "60001019983" | _                       | _                        | "Phone is not in coverage area"                  || "Teie mobiiltelefon on levialast väljas."

    }

    @Unroll
    @Feature("MID_AUTH_POLL_RESPONSE_COMPLETE")
    def "initialize mobile-ID authentication with scenario: #label ru"() {
        expect:
        LinkedHashMap<String, String> localeMap = (LinkedHashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(localeMap, "lang", "ru")
        Response initOIDCServiceSession = Steps.createSession(flow)
        Response loginSession = Steps.initLoginSession(flow, initOIDCServiceSession, localeMap)
        LinkedHashMap<String, String> additionalParamsMap = (LinkedHashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(additionalParamsMap, additionalParameterName, additionalParameterValue)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, idCode, phoneNo, additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 400, pollResponse.statusCode())
        assertThat(pollResponse.body().jsonPath().get("message"), Matchers.startsWith(errorMessage))

        where:
        phoneNo    | idCode        | additionalParameterName | additionalParameterValue | label                                            || errorMessage
        "00000266" | "60001019939" | _                       | _                        | "Mobile-ID user has no active certificates"      || "У пользователя отсутствует договор об услуге"
        "07110066" | "60001019947" | _                       | _                        | "Sending authentication request to phone failed" || "На Ваш телефон нельзя отправить сообщение аутентификации"
        "01100266" | "60001019950" | _                       | _                        | "User cancelled authentication"                  || "Аутентификация прервана"
        "00000666" | "60001019961" | _                       | _                        | "Created signature is not valid"                 || "Аутентификация с помощью Вашего"
        "01200266" | "60001019972" | _                       | _                        | "SIM application error"                          || "В SIM-карте Вашего телефона произошел сбой."
        "13100266" | "60001019983" | _                       | _                        | "Phone is not in coverage area"                  || "Ваш телефон находится вне зоны доступа."

    }

    @Unroll
    @Feature("MID_AUTH_POLL_RESPONSE_COMPLETE")
    def "initialize mobile-ID authentication with scenario: #label en"() {
        expect:
        LinkedHashMap<String, String> localeMap = (LinkedHashMap) Collections.emptyMap()
        def map1 = Utils.setParameter(localeMap, "lang", "en")
        Response initOIDCServiceSession = Steps.createSession(flow)
        Response loginSession = Steps.initLoginSession(flow, initOIDCServiceSession, localeMap)
        LinkedHashMap<String, String> additionalParamsMap = (LinkedHashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(additionalParamsMap, additionalParameterName, additionalParameterValue)
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, idCode, phoneNo, additionalParamsMap)
        assertEquals("Correct HTTP status code is returned", 200, initMidAuthenticationSession.statusCode())
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals("Correct HTTP status code is returned", 400, pollResponse.statusCode())
        assertThat(pollResponse.body().jsonPath().get("message"), Matchers.startsWith(errorMessage))

        where:
        phoneNo    | idCode        | additionalParameterName | additionalParameterValue | label                                            || errorMessage
        "00000266" | "60001019939" | _                       | _                        | "Mobile-ID user has no active certificates"      || "The user has no Mobile-ID contract."
        "07110066" | "60001019947" | _                       | _                        | "Sending authentication request to phone failed" || "Your mobile phone cannot receive Mobile-ID authentication messages."
        "01100266" | "60001019950" | _                       | _                        | "User cancelled authentication"                  || "Authentication has been cancelled."
        "00000666" | "60001019961" | _                       | _                        | "Created signature is not valid"                 || "Authentication with Mobile-ID failed. Test your Mobile-ID with the DigiDoc4 client"
        "01200266" | "60001019972" | _                       | _                        | "SIM application error"                          || "There was an error with your SIM card."
        "13100266" | "60001019983" | _                       | _                        | "Phone is not in coverage area"                  || "Your mobile phone is out of coverage area."

    }

}
