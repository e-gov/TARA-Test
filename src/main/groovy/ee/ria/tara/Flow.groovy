package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import ee.ria.tara.configuration.*
import groovy.transform.Canonical
import io.restassured.filter.cookie.CookieFilter
import io.restassured.path.json.JsonPath

@Canonical
class Flow {
    OidcService oidcService
    LoginService loginService
    OidcClient oidcClientPublic
    OidcClient oidcClientPost
    OidcClient oidcClientPrivate
    OidcClient oidcClientLegal
    SpecificProxyService specificProxyService
    ForeignIdpProvider foreignIdpProvider
    ForeignProxyService foreignProxyService
    TaraAdminService taraAdminService
 
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
        this.oidcClientPublic = new OidcClient(ConfigHolder.oidcClientPublic)
        this.oidcClientPost = new OidcClient(ConfigHolder.oidcClientPost)
        this.oidcClientPrivate = new OidcClient(ConfigHolder.oidcClientPrivate)
        this.oidcClientLegal = new OidcClient(ConfigHolder.oidcClientLegal)
        this.specificProxyService = new SpecificProxyService(ConfigHolder.specificProxyService)
        this.foreignIdpProvider = new ForeignIdpProvider(ConfigHolder.foreignIdp)
        this.foreignProxyService = new ForeignProxyService(ConfigHolder.caProxyService)
        this.taraAdminService = new TaraAdminService(ConfigHolder.adminService)
    }
}

@Canonical
class LoginService {
    String host
    String port
    String protocol
    String nodeHost
    String nodePort
    String nodeProtocol
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
    String heartbeatUrl
    String authLegalInitUrl
    String authLegalPersonUrl
    String authLegalConfirmUrl
    String errorUrl
    String eidasInitUrl
    String eidasCallbackUrl
    String idCardEndpointUsername
    String idCardEndpointPassword

    @Lazy baseUrl = "${protocol}://${host}"
    @Lazy fullBaseUrl = "${baseUrl}${Utils.portCheck(port)}"

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

    @Lazy fullHeartbeatUrl = "${nodeProtocol}://${nodeHost}${Utils.portCheck(nodePort)}${heartbeatUrl}"

    LoginService(LoginServiceConf conf) {
        this.host = conf.host()
        this.port = conf.port()
        this.protocol = conf.protocol()
        this.nodeHost = conf.nodeHost()
        this.nodePort = conf.nodePort()
        this.nodeProtocol = conf.nodeProtocol()
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
        this.heartbeatUrl = conf.heartbeatUrl()
        this.errorUrl = conf.errorUrl()
        this.eidasInitUrl = conf.eidasInitUrl()
        this.eidasCallbackUrl = conf.eidasCallbackUrl()
        this.authLegalInitUrl = conf.authLegalInitUrl()
        this.authLegalPersonUrl = conf.authLegalPersonUrl()
        this.authLegalConfirmUrl = conf.authLegalConfirmUrl()
        this.idCardEndpointUsername = conf.idUsername()
        this.idCardEndpointPassword = conf.idPassword()
    }
}

@Canonical
class OidcService {
    String host
    String protocol
    String authorizationUrl
    String jwksUrl
    String configurationUrl
    Map cookies

    @Lazy baseUrl = "${protocol}://${host}"

    @Lazy fullAuthorizationUrl = "${baseUrl}${authorizationUrl}"
    @Lazy fullJwksUrl = "${baseUrl}${jwksUrl}"
    @Lazy fullConfigurationUrl = "${baseUrl}${configurationUrl}"

    OidcService(OidcServiceConf conf) {
        this.host = conf.host()
        this.protocol = conf.protocol()
        this.authorizationUrl = conf.authorizationUrl()
        this.jwksUrl = conf.jwksUrl()
        this.configurationUrl = conf.configurationUrl()
        this.cookies = new HashMap()
    }
}

@Canonical
class OidcClient {
    String host
    String port
    String protocol
    String responseUrl
    String clientId
    String clientSecret
    Map cookies

    @Lazy fullResponseUrl = "${protocol}://${host}${Utils.portCheck(port)}${responseUrl}"

    OidcClient(OidcClientConf conf) {
        this.host = conf.host()
        this.port = conf.port()
        this.protocol = conf.protocol()
        this.responseUrl = conf.responseUrl()
        this.clientId = conf.clientId()
        this.clientSecret = conf.secret()
        this.cookies = new HashMap()
    }
}

@Canonical
class SpecificProxyService {
    String host
    String port
    String protocol
    String responseUrl
    String clientId
    String clientSecret
    Map cookies

    @Lazy fullResponseUrl = "${protocol}://${host}${Utils.portCheck(port)}${responseUrl}"

    SpecificProxyService(SpecificProxyServiceConf conf) {
        this.host = conf.host()
        this.port = conf.port()
        this.protocol = conf.protocol()
        this.responseUrl = conf.responseUrl()
        this.clientId = conf.clientId()
        this.clientSecret = conf.secret()
        this.cookies = new HashMap()
    }
}

@Canonical
class ForeignIdpProvider {
    String host
    String port
    String protocol
    String responseUrl
    @Lazy fullResponseUrl = "${protocol}://${host}${Utils.portCheck(port)}${responseUrl}"

    ForeignIdpProvider(ForeignIdpConf conf) {
        this.host = conf.host()
        this.port = conf.port()
        this.protocol = conf.protocol()
        this.responseUrl = conf.responseUrl()
    }
}

@Canonical
class ForeignProxyService {
    String host
    String port
    String protocol
    String consentUrl

    @Lazy fullConsentUrl = "${protocol}://${host}${Utils.portCheck(port)}${consentUrl}"

    ForeignProxyService(CaProxyServiceConf conf) {
        this.host = conf.host()
        this.port = conf.port()
        this.protocol = conf.protocol()
        this.consentUrl = conf.consentUrl()
    }
}

@Canonical
class TaraAdminService {
    String host
    String port
    String protocol
    String username
    String password
    String xsrfToken
    String jsessionId

    @Lazy fullBaseUrl = "${protocol}://${host}${Utils.portCheck(port)}"

    TaraAdminService(AdminServiceConf conf) {
        this.host = conf.host()
        this.port = conf.port()
        this.protocol = conf.protocol()
        this.username = conf.username()
        this.password = conf.password()
    }
}
