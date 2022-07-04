package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Ignore
import spock.lang.Unroll

import static org.junit.jupiter.api.Assertions.assertEquals


@Ignore
class TaraAdminSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("TARA_MGMT_CLIENT_ADD_RESPONSE_SUCCESS")
    @Feature("TARA_MGMT_ADDCLIENT_UPDATEINSTITUTION")
    def "Register new organisation and client application"() {
        expect:
        TaraAdminSteps.taraAdminLogin(flow, flow.taraAdminService.username, flow.taraAdminService.password)
        Response myResponse = TaraAdminSteps.whoAmI(flow)
        assertEquals(flow.taraAdminService.username, myResponse.getBody().jsonPath().get("username"), "Correct authenticated user")
        String registryCode = "75004381"
        String clientId = "rak_id"

        TaraAdminSteps.deleteClient(flow, registryCode, clientId, false)
        sleep(2000L)
        TaraAdminSteps.deleteInstitution(flow, registryCode, false)

        TaraAdminSteps.createInstitution(flow, registryCode)
        sleep(2000L)
        TaraAdminSteps.addClientApplication(flow, registryCode, clientId)
    }
}
