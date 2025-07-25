package ee.ria.tara


import org.opensaml.core.config.InitializationService
import spock.lang.Specification

class TaraSpecification extends Specification {
    static {
        new BeforeAll()
    }

    Flow flow = new Flow()

    static final IDP_USERNAME = "xavi"
    static final IDP_PASSWORD = "creus"
    static final COUNTRY_CA = "CA"

    def setupSpec() {
        InitializationService.initialize()
    }
}
