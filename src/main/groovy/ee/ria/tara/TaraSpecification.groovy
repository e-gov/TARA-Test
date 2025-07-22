package ee.ria.tara


import org.opensaml.core.config.InitializationService
import spock.lang.Specification

class TaraSpecification extends Specification {
    static {
        new BeforeAll()
    }

    Flow flow = new Flow()

    static final REQUEST_TYPE_POST = "post"
    static final REQUEST_TYPE_GET = "get"
    static final IDP_USERNAME = "xavi"
    static final IDP_PASSWORD = "creus"
    static final EIDASLOA_HIGH = "E"
    static final EIDASLOA_SUBSTANTIAL = "C"
    static final EIDASLOA_LOW = "A"
    static final EIDASLOA_NOT_NOTIFIED = "http://non.eidas.eu/NotNotified/LoA/1"
    static final COUNTRY_CA = "CA"

    def setupSpec() {
        InitializationService.initialize()
    }
}
