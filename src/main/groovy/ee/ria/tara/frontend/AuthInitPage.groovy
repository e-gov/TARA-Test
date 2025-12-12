package ee.ria.tara.frontend

import com.microsoft.playwright.Page
import com.microsoft.playwright.Request
import com.microsoft.playwright.options.LoadState
import com.microsoft.playwright.options.WaitForSelectorState
import ee.ria.tara.Flow
import ee.ria.tara.Utils
import ee.ria.tara.model.Client
import groovy.transform.Canonical
import io.qameta.allure.Step

import java.util.function.Predicate

@Canonical
class AuthInitPage {

    Page page
    Flow flow

    @Step("Open Tara login init page")
    void openAuthInit(Client client) {
        page.navigate(Utils.getTaraLoginUrl(flow, client))
        page.waitForLoadState(LoadState.LOAD)
    }

    void selectIdCard() {
        page.click("a[data-tab='id-card']")
    }

    void selectMid() {
        page.click("a[data-tab='mobile-id']")
    }

    void selectSid() {
        page.click("a[data-tab='smart-id']")
        Utils.isMobile(page)
    }

    void selectEidas() {
        page.click("a[data-tab='eu-citizen']")
    }

    // TODO: set default personal code
    void initSidAuth(String personalCode) {
        selectSid()
        AuthInitSidComponent sidAuth = new AuthInitSidComponent(page, flow)
        sidAuth.enterPersonalCode(personalCode)
        sidAuth.enter()
    }
}

@Canonical
class AuthInitSidComponent {
    Page page
    Flow flow

    void enterPersonalCode(String personalCode) {
        page.fill("#sid-personal-code", personalCode)
    }

    void enter() {
        page.press("#sid-personal-code", "Enter")
    }

    void clickContinue() {
        page.click("form#smartIdForm button")
    }
}

@Canonical
class SidInitPage {
    Page page
    Flow flow

    void clickCancel() {
        page.click("form#midAuthenticationCheckForm button")
    }

    String waitForAuthorizationCode(Client client) {
        Request finalRequest = page.waitForRequest(
                { Request req -> req.url().startsWith(client.redirectUri) } as Predicate<Request>,
                null,
                {
                    page.waitForSelector("#midAuthenticationCheckForm", new Page.WaitForSelectorOptions()
                            .setState(WaitForSelectorState.DETACHED))
                }
        )

        def queryParams = new URI(finalRequest.url()).query.split("&")*.split("=", 2)
        String authorizationCode = queryParams.find { it[0] == "code" }?.with { URLDecoder.decode(it[1], "UTF-8") }
        return authorizationCode
    }
}
