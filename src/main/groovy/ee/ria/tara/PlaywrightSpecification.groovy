package ee.ria.tara

import com.microsoft.playwright.Page

abstract class PlaywrightSpecification extends TaraSpecification {

    TestBrowser testBrowser
    Page page

    def setup() {
        testBrowser = new TestBrowser(TestBrowser.defaultBrowserContextOptions)
        testBrowser.testName = specificationContext.currentIteration.displayName
        page = testBrowser.page
    }

    def cleanup() {
        testBrowser.close()
    }
}
