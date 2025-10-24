package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import ee.ria.tara.configuration.*
import groovy.transform.Canonical
import io.restassured.filter.cookie.CookieFilter
import io.restassured.path.json.JsonPath

@Canonical
abstract class BaseService {
    String protocol
    String host
    String port

    String nodeProtocol
    String nodeHost
    String nodePort

    @Lazy baseUrl = "${protocol}://${host}"
    @Lazy fullBaseUrl = "${baseUrl}${Utils.portCheck(port)}"
    @Lazy fullNodeUrl = "${nodeProtocol}://${nodeHost}${Utils.portCheck(nodePort)}"

    BaseService(conf) {
        this.protocol = conf.protocol()
        this.host = conf.host()
        this.port = conf.port()

        switch (conf) {
            case InproxyServiceConf: // fall through
            case CaProxyServiceConf: // fall through
            case AdminServiceConf: // fall through
            case ForeignIdpConf: // fall through
            case DemoClientConf:
                this.nodeProtocol = this.protocol
                this.nodeHost = this.host
                this.nodePort = this.port
                break
            default:
                this.nodeProtocol = conf.nodeProtocol()
                this.nodeHost = conf.nodeHost()
                this.nodePort = conf.nodePort()
        }
    }
}

@Canonical
class LoginService extends BaseService {
    String initUrl
    String midInitUrl
    String midPollUrl
    String midCancelUrl
    String webEidInitUrl
    String webEidLoginUrl
    String sidInitUrl
    String sidPollUrl
    String sidCancelUrl
    String authAcceptUrl
    String authRejectUrl
    String consentUrl
    String consentConfirmUrl
    String authLegalInitUrl
    String authLegalPersonUrl
    String authLegalConfirmUrl
    String errorUrl
    String eidasInitUrl
    String eidasCallbackUrl
    String idCardEndpointUsername
    String idCardEndpointPassword

    @Lazy fullWebEidInitUrl = "${baseUrl}${webEidInitUrl}"
    @Lazy fullWebEidLoginUrl = "${baseUrl}${webEidLoginUrl}"

    @Lazy fullInitUrl = "${fullBaseUrl}${initUrl}"
    @Lazy fullMidInitUrl = "${fullBaseUrl}${midInitUrl}"
    @Lazy fullMidPollUrl = "${fullBaseUrl}${midPollUrl}"
    @Lazy fullMidCancelUrl = "${fullBaseUrl}${midCancelUrl}"
    @Lazy fullSidInitUrl = "${fullBaseUrl}${sidInitUrl}"
    @Lazy fullSidPollUrl = "${fullBaseUrl}${sidPollUrl}"
    @Lazy fullSidCancelUrl = "${fullBaseUrl}${sidCancelUrl}"
    @Lazy fullAuthAcceptUrl = "${fullBaseUrl}${authAcceptUrl}"
    @Lazy fullAuthRejectUrl = "${fullBaseUrl}${authRejectUrl}"
    @Lazy fullConsentUrl = "${fullBaseUrl}${consentUrl}"
    @Lazy fullConsentConfirmUrl = "${fullBaseUrl}${consentConfirmUrl}"
    @Lazy fullErrorUrl = "${fullBaseUrl}${errorUrl}"
    @Lazy fullEidasInitUrl = "${fullBaseUrl}${eidasInitUrl}"
    @Lazy fullAuthLegalInitUrl = "${fullBaseUrl}${authLegalInitUrl}"
    @Lazy fullAuthLegalPersonUrl = "${fullBaseUrl}${authLegalPersonUrl}"
    @Lazy fullAuthLegalConfirmUrl = "${fullBaseUrl}${authLegalConfirmUrl}"

    LoginService(LoginServiceConf conf) {
        super(conf)
        this.initUrl = conf.initUrl()
        this.midInitUrl = conf.midInitUrl()
        this.midPollUrl = conf.midPollUrl()
        this.midCancelUrl = conf.midCancelUrl()
        this.webEidInitUrl = conf.webEidInitUrl()
        this.webEidLoginUrl = conf.webEidLoginUrl()
        this.sidInitUrl = conf.sidInitUrl()
        this.sidPollUrl = conf.sidPollUrl()
        this.sidCancelUrl = conf.sidCancelUrl()
        this.authAcceptUrl = conf.authAcceptUrl()
        this.authRejectUrl = conf.authRejectUrl()
        this.consentUrl = conf.consentUrl()
        this.consentConfirmUrl = conf.consentConfirmUrl()
        this.errorUrl = conf.errorUrl()
        this.eidasInitUrl = conf.eidasInitUrl()
        this.eidasCallbackUrl = conf.eidasCallbackUrl()
        this.authLegalInitUrl = conf.authLegalInitUrl()
        this.authLegalPersonUrl = conf.authLegalPersonUrl()
        this.authLegalConfirmUrl = conf.authLegalConfirmUrl()
        this.idCardEndpointUsername = conf.idUsername()
        this.idCardEndpointPassword = conf.idPassword()
    }

    @Override
    String toString() {
        return "Login service"
    }
}

@Canonical
class OidcService extends BaseService {
    String authorizationUrl
    String jwksUrl
    String configurationUrl
    Map cookies = [:]

    @Lazy fullAuthorizationUrl = "${baseUrl}${authorizationUrl}"
    @Lazy fullJwksUrl = "${baseUrl}${jwksUrl}"
    @Lazy fullConfigurationUrl = "${baseUrl}${configurationUrl}"

    OidcService(OidcServiceConf conf) {
        super(conf)
        this.authorizationUrl = conf.authorizationUrl()
        this.jwksUrl = conf.jwksUrl()
        this.configurationUrl = conf.configurationUrl()
    }

    @Override
    String toString() {
        return "OIDC service"
    }
}

@Canonical
class ForeignIdpProvider extends BaseService {
    String responseUrl

    @Lazy fullResponseUrl = "${fullBaseUrl}${responseUrl}"

    ForeignIdpProvider(ForeignIdpConf conf) {
        super(conf)
        this.responseUrl = conf.responseUrl()
    }
}

@Canonical
class ForeignProxyService extends BaseService {
    String consentUrl

    @Lazy fullConsentUrl = "${fullBaseUrl}${consentUrl}"

    ForeignProxyService(CaProxyServiceConf conf) {
        super(conf)
        this.consentUrl = conf.consentUrl()
    }
}

@Canonical
class TaraAdminService extends BaseService {
    String username
    String password
    String xsrfToken
    String jsessionId

    TaraAdminService(AdminServiceConf conf) {
        super(conf)
        this.username = conf.username()
        this.password = conf.password()
    }

    @Override
    String toString() {
        return "Tara admin"
    }
}

@Canonical
class InproxyService extends BaseService {

    InproxyService(InproxyServiceConf conf) {
        super(conf)
    }

    @Override
    String toString() {
        return "Inproxy service"
    }
}

@Canonical
class DemoClient extends BaseService {

    DemoClient(DemoClientConf conf) {
        super(conf)
    }

    @Override
    String toString() {
        return "Demo client"
    }
}

@Canonical
class Flow {
    OidcService oidcService
    LoginService loginService
    ForeignIdpProvider foreignIdpProvider
    ForeignProxyService foreignProxyService
    TaraAdminService taraAdminService
    InproxyService inproxyService

    CookieFilter cookieFilter
    String clientId
    String clientSecret
    String redirectUri
    String sessionId
    String code
    String locale
    String csrf
    String loginChallenge
    String authCertificate

    String state
    String nonce
    JWKSet jwkSet
    JsonPath openIdServiceConfiguration

    String nextEndpoint
    String requestMessage
    String responseMessage
    String relayState

    Flow() {
        this.loginService = new LoginService(ConfigHolder.loginService)
        this.oidcService = new OidcService(ConfigHolder.oidcService)
        this.foreignIdpProvider = new ForeignIdpProvider(ConfigHolder.foreignIdp)
        this.foreignProxyService = new ForeignProxyService(ConfigHolder.caProxyService)
        this.taraAdminService = new TaraAdminService(ConfigHolder.adminService)
        this.inproxyService = new InproxyService(ConfigHolder.inproxyService)
    }
}
