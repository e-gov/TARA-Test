package ee.ria.tara.configuration

import org.aeonbits.owner.Config
import org.aeonbits.owner.Config.Key

interface TestConf extends Config {
    @Key("test.restAssured.consoleLogging")
    Boolean restAssuredConsoleLogging()
}
