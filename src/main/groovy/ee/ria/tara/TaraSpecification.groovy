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
    static final REJECT_ERROR_CODE = "user_cancel"
    static final IDP_USERNAME = "xavi"
    static final IDP_PASSWORD = "creus"
    static final EIDASLOA_HIGH = "E"
    static final EIDASLOA_SUBSTANTIAL = "C"
    static final EIDASLOA_LOW = "A"
    static final EIDASLOA_NOT_NOTIFIED = "http://non.eidas.eu/NotNotified/LoA/1"
    static final COUNTRY_CA = "CA"

    static final ERROR_UNAUTHORIZED = "request_unauthorized"
    static final ERROR_UNAUTHORIZED_CLIENT = "unauthorized_client"
    static final ERROR_SCOPE = "invalid_scope"
    static final ERROR_GRANT = "invalid_grant"
    static final ERROR_STATE = "invalid_state"
    static final ERROR_CLIENT = "invalid_client"
    static final ERROR_REQUEST = "invalid_request"
    static final ERROR_SERVICE = "service_error"

    def setupSpec() {
        InitializationService.initialize()
    }
}
