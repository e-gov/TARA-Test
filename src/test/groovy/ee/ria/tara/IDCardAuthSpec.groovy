package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import spock.lang.Ignore
import spock.lang.Unroll


class IDCardAuthSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Ignore
    @Unroll
    @Feature("ESTEID_AUTH_ENDPOINT")
    def "Init ID-Card authentication"() {
        expect:
        String certificate = Utils.getCertificateAsString("src/test/resources/joeorg-auth.pem")
        Response initClientAuthenticationSession = Steps.initAuthenticationSession(flow)
        HashMap<String, String> headersMap = (HashMap) Collections.emptyMap()
        def map2 = Utils.setParameter(headersMap, "XCLIENTCERTIFICATE", certificate)
        Response response = Requests.idCardAuthentication(flow, headersMap)
        // TODO implement correct flow
        /*
        {
            "timestamp": "2021-01-04T09:36:37.383+00:00",
            "status": 400,
            "error": "Bad Request",
            "message": "Sertifikaadi küsimine ei õnnestunud. Palun proovige mõne aja pärast uuesti.",
            "path": "/auth/id",
            "locale": "en_US"
        }
         */
    }

}
