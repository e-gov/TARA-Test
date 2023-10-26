package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import groovy.transform.Canonical
import io.restassured.filter.cookie.CookieFilter
import io.restassured.path.json.JsonPath

@Canonical
class Flow {
    Properties properties
    OidcService oidcService
    LoginService loginService
    OidcClientPublic oidcClientPublic
    OidcClientPost oidcClientPost
    OidcClientPrivate oidcClientPrivate
    OidcClientLegal oidcClientLegal
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
    String login_locale
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

    Flow(Properties properties) {
        this.properties = properties
        this.loginService = new LoginService(properties)
        this.oidcService = new OidcService(properties)
        this.oidcClientPublic = new OidcClientPublic(properties)
        this.oidcClientPost = new OidcClientPost(properties)
        this.oidcClientPrivate = new OidcClientPrivate(properties)
        this.oidcClientLegal = new OidcClientLegal(properties)
        this.specificProxyService = new SpecificProxyService(properties)
        this.foreignIdpProvider = new ForeignIdpProvider(properties)
        this.foreignProxyService = new ForeignProxyService(properties)
        this.taraAdminService = new TaraAdminService(properties)
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

    @Lazy fullInitUrl = "${protocol}://${host}${portCheck()}${initUrl}"
    @Lazy fullMidInitUrl = "${protocol}://${host}${portCheck()}${midInitUrl}"
    @Lazy fullMidPollUrl = "${protocol}://${host}${portCheck()}${midPollUrl}"
    @Lazy fullMidCancelUrl = "${protocol}://${host}${portCheck()}${midCancelUrl}"
    @Lazy fullWebEidInitUrl = "${protocol}://${host}${webEidInitUrl}"
    @Lazy fullWebEidLoginUrl = "${protocol}://${host}${webEidLoginUrl}"
    @Lazy fullSidInitUrl = "${protocol}://${host}${portCheck()}${sidInitUrl}"
    @Lazy fullSidPollUrl = "${protocol}://${host}${portCheck()}${sidPollUrl}"
    @Lazy fullSidCancelUrl = "${protocol}://${host}${portCheck()}${sidCancelUrl}"
    @Lazy fullAuthAcceptUrl = "${protocol}://${host}${portCheck()}${authAcceptUrl}"
    @Lazy fullAuthRejectUrl = "${protocol}://${host}${portCheck()}${authRejectUrl}"
    @Lazy fullConsentUrl = "${protocol}://${host}${portCheck()}${consentUrl}"
    @Lazy fullConsentConfirmUrl = "${protocol}://${host}${portCheck()}${consentConfirmUrl}"
    @Lazy fullHeartbeatUrl = "${nodeProtocol}://${nodeHost}${nodePortCheck()}${heartbeatUrl}"
    @Lazy fullErrorUrl = "${protocol}://${host}${portCheck()}${errorUrl}"
    @Lazy fullEidasInitUrl = "${protocol}://${host}${portCheck()}${eidasInitUrl}"
    @Lazy fullAuthLegalInitUrl = "${protocol}://${host}${portCheck()}${authLegalInitUrl}"
    @Lazy fullAuthLegalPersonUrl = "${protocol}://${host}${portCheck()}${authLegalPersonUrl}"
    @Lazy fullAuthLegalConfirmUrl = "${protocol}://${host}${portCheck()}${authLegalConfirmUrl}"
    @Lazy baseUrl = "${protocol}://${host}"

    LoginService(Properties properties) {
        this.host = properties."loginservice.host"
        this.port = properties."loginservice.port"
        this.protocol = properties."loginservice.protocol"
        this.nodeHost = properties."loginservice.node.host"
        this.nodePort = properties."loginservice.node.port"
        this.nodeProtocol = properties."loginservice.node.protocol"
        this.initUrl = properties."loginservice.initUrl"
        this.midInitUrl = properties."loginservice.midInitUrl"
        this.midPollUrl = properties."loginservice.midPollUrl"
        this.midCancelUrl = properties."loginservice.midCancelUrl"
        this.webEidInitUrl = properties."loginservice.webEidInitUrl"
        this.webEidLoginUrl = properties."loginservice.webEidLoginUrl"
        this.sidInitUrl = properties."loginservice.sidInitUrl"
        this.sidPollUrl = properties."loginservice.sidPollUrl"
        this.sidCancelUrl = properties."loginservice.sidCancelUrl"
        this.authAcceptUrl = properties."loginservice.authAcceptUrl"
        this.authRejectUrl = properties."loginservice.authRejectUrl"
        this.consentUrl = properties."loginservice.consentUrl"
        this.consentConfirmUrl = properties."loginservice.consentConfirmUrl"
        this.heartbeatUrl = properties."loginservice.heartbeatUrl"
        this.errorUrl = properties."loginservice.errorUrl"
        this.eidasInitUrl = properties."loginservice.eidasInitUrl"
        this.eidasCallbackUrl = properties."loginservice.eidasCallbackUrl"
        this.authLegalInitUrl = properties."loginservice.authLegalInitUrl"
        this.authLegalPersonUrl = properties."loginservice.authLegalPersonUrl"
        this.authLegalConfirmUrl = properties."loginservice.authLegalConfirmUrl"
        this.idCardEndpointUsername = properties."loginservice.id.username"
        this.idCardEndpointPassword = properties."loginservice.id.password"
    }
    private String portCheck() {
        if (port != null && port.isInteger()) {
            return ":${port}"
        } else {
            return ""
        }
    }

    private String nodePortCheck() {
        if (nodePort != null && nodePort.isInteger()) {
            return ":${nodePort}"
        } else {
            return ""
        }
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

    @Lazy fullAuthorizationUrl = "${protocol}://${host}${authorizationUrl}"
    @Lazy fullJwksUrl = "${protocol}://${host}${jwksUrl}"
    @Lazy fullConfigurationUrl = "${protocol}://${host}${configurationUrl}"
    @Lazy baseUrl = "${protocol}://${host}"

    OidcService(Properties properties) {
        this.host = properties."oidcservice.host"
        this.protocol = properties."oidcservice.protocol"
        this.authorizationUrl = properties."oidcservice.authorizationUrl"
        this.jwksUrl = properties."oidcservice.jwksUrl"
        this.configurationUrl = properties."oidcservice.configurationUrl"
        this.cookies = new HashMap()
    }
}

@Canonical
class OidcClientPublic {
    String host
    String port
    String protocol
    String responseUrl
    String clientId
    String clientSecret
    Map cookies

    @Lazy fullResponseUrl = "${protocol}://${host}${portCheck()}${responseUrl}"

    OidcClientPublic(Properties properties) {
        this.host = properties."oidcclientpublic.host"
        this.port = properties."oidcclientpublic.port"
        this.protocol = properties."oidcclientpublic.protocol"
        this.responseUrl = properties."oidcclientpublic.responseUrl"
        this.clientId = properties."oidcclientpublic.clientId"
        this.clientSecret = properties."oidcclientpublic.secret"
        this.cookies = new HashMap()
    }
    private String portCheck() {
        if (port != null && port.isInteger()) {
            return ":${port}"
        } else {
            return ""
        }
    }
}

@Canonical
class OidcClientPost {
    String host
    String port
    String protocol
    String responseUrl
    String clientId
    String clientSecret
    Map cookies

    @Lazy fullResponseUrl = "${protocol}://${host}${portCheck()}${responseUrl}"

    OidcClientPost(Properties properties) {
        this.host = properties."oidcclientpost.host"
        this.port = properties."oidcclientpost.port"
        this.protocol = properties."oidcclientpost.protocol"
        this.responseUrl = properties."oidcclientpost.responseUrl"
        this.clientId = properties."oidcclientpost.clientId"
        this.clientSecret = properties."oidcclientpost.secret"
        this.cookies = new HashMap()
    }
    private String portCheck() {
        if (port != null && port.isInteger()) {
            return ":${port}"
        } else {
            return ""
        }
    }
}

@Canonical
class OidcClientPrivate {
    String host
    String port
    String protocol
    String responseUrl
    String clientId
    String clientSecret
    Map cookies

    @Lazy fullResponseUrl = "${protocol}://${host}${portCheck()}${responseUrl}"

    OidcClientPrivate(Properties properties) {
        this.host = properties."oidcclientprivate.host"
        this.port = properties."oidcclientprivate.port"
        this.protocol = properties."oidcclientprivate.protocol"
        this.responseUrl = properties."oidcclientprivate.responseUrl"
        this.clientId = properties."oidcclientprivate.clientId"
        this.clientSecret = properties."oidcclientprivate.secret"
        this.cookies = new HashMap()
    }
    private String portCheck() {
        if (port != null && port.isInteger()) {
            return ":${port}"
        } else {
            return ""
        }
    }
}

@Canonical
class OidcClientLegal {
    String host
    String port
    String protocol
    String responseUrl
    String clientId
    String clientSecret
    Map cookies

    @Lazy fullResponseUrl = "${protocol}://${host}${portCheck()}${responseUrl}"

    OidcClientLegal(Properties properties) {
        this.host = properties."oidcclientlegal.host"
        this.port = properties."oidcclientlegal.port"
        this.protocol = properties."oidcclientlegal.protocol"
        this.responseUrl = properties."oidcclientlegal.responseUrl"
        this.clientId = properties."oidcclientlegal.clientId"
        this.clientSecret = properties."oidcclientlegal.secret"
        this.cookies = new HashMap()
    }
    private String portCheck() {
        if (port != null && port.isInteger()) {
            return ":${port}"
        } else {
            return ""
        }
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

    @Lazy fullResponseUrl = "${protocol}://${host}${portCheck()}${responseUrl}"

    SpecificProxyService(Properties properties) {
        this.host = properties."specificproxyservice.host"
        this.port = properties."specificproxyservice.port"
        this.protocol = properties."specificproxyservice.protocol"
        this.responseUrl = properties."specificproxyservice.responseUrl"
        this.clientId = properties."specificproxyservice.clientId"
        this.clientSecret = properties."specificproxyservice.secret"
        this.cookies = new HashMap()
    }
    private String portCheck() {
        if (port != null && port.isInteger()) {
            return ":${port}"
        } else {
            return ""
        }
    }
}

@Canonical
class ForeignIdpProvider {
    String host
    String port
    String protocol
    String responseUrl
    @Lazy fullResponseUrl = "${protocol}://${host}${portCheck()}${responseUrl}"

    ForeignIdpProvider(Properties properties) {
        this.host = properties."idp.host"
        this.port = properties."idp.port"
        this.protocol = properties."idp.protocol"
        this.responseUrl = properties."idp.responseUrl"
    }
    private String portCheck() {
        if (port != null && port.isInteger()) {
            return ":${port}"
        } else {
            return ""
        }
    }
}

@Canonical
class ForeignProxyService {
    String host
    String port
    String protocol
    String consentUrl

    @Lazy fullConsentUrl = "${protocol}://${host}${portCheck()}${consentUrl}"

    ForeignProxyService(Properties properties) {
        this.host = properties."ca-proxyservice.host"
        this.port = properties."ca-proxyservice.port"
        this.protocol = properties."ca-proxyservice.protocol"
        this.consentUrl = properties."ca-proxyservice.consentUrl"
    }
    private String portCheck() {
        if (port != null && port.isInteger()) {
            return ":${port}"
        } else {
            return ""
        }
    }
}

@Canonical
class TaraAdminService {
    String host
    String port
    String protocol
    String baseUrl
    String username
    String password
    String xsrfToken
    String jsessionId

    @Lazy fullBaseUrl = "${protocol}://${host}${portCheck()}"

    TaraAdminService(Properties properties) {
        this.host = properties."adminservice.host"
        this.port = properties."adminservice.port"
        this.protocol = properties."adminservice.protocol"
        this.username = properties."adminservice.username"
        this.password = properties."adminservice.password"
    }
    private String portCheck() {
        if (port != null && port.isInteger()) {
            return ":${port}"
        } else {
            return ""
        }
    }
}
