package ee.ria.tara

import com.microsoft.playwright.Browser
import com.microsoft.playwright.BrowserContext
import com.microsoft.playwright.BrowserType
import com.microsoft.playwright.Page
import com.microsoft.playwright.Playwright
import com.microsoft.playwright.Tracing
import ee.ria.tara.configuration.ConfigHolder
import ee.ria.tara.configuration.TestConf
import ee.ria.tara.util.MyBrowserType

import java.nio.file.Paths

/**
 * Playwright wrapper for cases where using PwSpec is not reasonable or possible.
 */
class TestBrowser implements Closeable {

    TestConf conf = ConfigHolder.getTestConf()
    Playwright playwright
    Browser browser
    BrowserContext browserContext
    Page page
    String testName

    TestBrowser(Browser.NewContextOptions browserContextOptions) {
        this(MyBrowserType.CHROMIUM, browserContextOptions)
    }

    TestBrowser(MyBrowserType browserType, Browser.NewContextOptions browserContextOptions) {
        playwright = Playwright.create()
        browser = switch (browserType) {
            case MyBrowserType.CHROME -> playwright.chromium().launch(getLaunchOptions().setChannel("chrome"))
            case MyBrowserType.CHROMIUM -> playwright.chromium().launch(getLaunchOptions())
            case MyBrowserType.EDGE -> playwright.chromium().launch(getLaunchOptions().setChannel("msedge"))
            case MyBrowserType.FIREFOX -> playwright.firefox().launch(getLaunchOptions())
            case MyBrowserType.WEBKIT -> playwright.webkit().launch(getLaunchOptions())
        }

        browserContext = browser.newContext(browserContextOptions)
        startTrace()
        page = browserContext.newPage()
    }

    @Override
    void close() throws IOException {
        page?.close()
        endTrace()
        browserContext?.close()
        browser?.close()
        playwright?.close()
    }

    BrowserType.LaunchOptions getLaunchOptions() {
        BrowserType.LaunchOptions launchOptions = new BrowserType.LaunchOptions()
        if (conf.debug()) {
            launchOptions.setHeadless(false)
            launchOptions.setSlowMo(500)
        }
        return launchOptions
    }

    static Browser.NewContextOptions getDefaultBrowserContextOptions() {
        new Browser.NewContextOptions()
                .setIgnoreHTTPSErrors(true)
                .setViewportSize(1920, 1080)
                .setAcceptDownloads(true)
    }

    void startTrace() {
        if (conf.pwTrace()) {
            browserContext.tracing().start(new Tracing.StartOptions()
                    .setScreenshots(true)
                    .setSnapshots(true)
                    .setSources(true))
        }
    }

    void endTrace() {
        // TODO: save trace only on test failure - requires writing spock extension
        if (conf.pwTrace()) {
            def tracePath = Paths.get("target/playwright-trace/${testName}.zip")
            try {
                browserContext.tracing().stop(new Tracing.StopOptions().setPath(tracePath))
                // TODO: link to Playwright trace in Allure report
//                Allure.link("View Playwright trace", "https://trace.playwright.dev/?trace=${conf.pwTraceUrl()}/${testName}.zip")
                println("Playwright trace stored at: ${System.getProperty("user.dir")}\\${tracePath}")
                println("To view the report, run: \nmvn exec:java -e -D exec.mainClass=com.microsoft.playwright.CLI -D exec.args='show-trace ${tracePath}'")
            } catch (Exception e) {
                println("Failed to stop playwright tracing. Tracing might not have been started.")
                println("Exception: ${e}")
            }
        }
    }
}
