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

    static final ERROR_BAD_REQUEST = "Bad Request"
    static final ERROR_FORBIDDEN = "Forbidden"
    static final ERROR_UNAUTHORIZED = "request_unauthorized"
    static final ERROR_UNAUTHORIZED_CLIENT = "unauthorized_client"
    static final ERROR_INTERNAL = "Internal Server Error"
    static final ERROR_SCOPE = "invalid_scope"
    static final ERROR_GRANT = "invalid_grant"
    static final ERROR_STATE = "invalid_state"
    static final ERROR_CLIENT = "invalid_client"
    static final ERROR_REQUEST = "invalid_request"
    static final ERROR_SERVICE = "service_error"

    static final MESSAGE_SESSION_NOT_FOUND = "Teie seanssi ei leitud! Seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."
    static final MESSAGE_FORBIDDEN_REQUEST = "Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."
    static final MESSAGE_INTERNAL_ERROR = "Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."
    static final MESSAGE_DUPLICATE_PARAMETERS = "Multiple request parameters with the same name not allowed"
    static final MESSAGE_INCORRECT_REQUEST = "Ebakorrektne päring."
    static final MESSAGE_INCORRECT_ID_CODE = "Teie poolt sisestatud isikukood ei olnud korrektne. Palun pöörduge tagasi autentimismeetodite valiku juurde ja veenduge, et sisestate korrektse isikukoodi."

    def setupSpec() {
        InitializationService.initialize()
    }
}
