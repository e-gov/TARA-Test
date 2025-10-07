package ee.ria.tara.admin

import ee.ria.tara.TaraAdminSteps
import ee.ria.tara.TaraSpecification
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import org.apache.http.HttpStatus

import static org.hamcrest.Matchers.is

class AdminSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Feature("TARA_MGMT")
    def "Login to TARA admin succeeds"() {
        when:
        TaraAdminSteps.taraAdminLogin(flow, flow.taraAdminService.username, flow.taraAdminService.password)

        then:
        TaraAdminSteps.whoAmIRequest(flow).then()
                .statusCode(HttpStatus.SC_OK)
                .body("username", is(flow.taraAdminService.username))
    }
}
