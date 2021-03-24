package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import spock.lang.IgnoreIf
import spock.lang.Unroll

import static org.junit.Assert.assertEquals


@IgnoreIf({ properties['test.deployment.env'] == "idp" })
class TaraAdminSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("TARA_MGMT_CLIENT_ADD_RESPONSE_SUCCESS")
    def "Register new organisation and client application"() {
        expect:
        TaraAdminSteps.taraAdminLogin(flow, flow.taraAdminService.username, flow.taraAdminService.password)
        Response myResponse = TaraAdminSteps.whoAmI(flow)
        assertEquals("Correct authenticated user", flow.taraAdminService.username, myResponse.getBody().jsonPath().get("username"))
        String registryCode = "75004381"
        String clientId = "rak_id"

        TaraAdminSteps.deleteClient(flow, registryCode, clientId, false)
        TaraAdminSteps.deleteInstitution(flow, registryCode, false)

        TaraAdminSteps.createInstitution(flow, registryCode)
        TaraAdminSteps.addClientApplication(flow, registryCode, clientId)
    }
}
