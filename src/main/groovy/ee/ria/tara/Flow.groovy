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
    OidcClient oidcClient
    ForeignIdpProvider foreignIdpProvider
    ForeignProxyService foreignProxyService
    TaraAdminService taraAdminService
 
    CookieFilter cookieFilter
    String sessionId
    String login_locale
    String csrf
    String loginChallenge

    String state
    String nonce
    JWKSet jwkSet
    JsonPath openIdServiceConfiguration

    String nextEndpoint
    String requestMessage
    String relayState

    Flow(Properties properties) {
        this.properties = properties
        this.loginService = new LoginService(properties)
        this.oidcService = new OidcService(properties)
        this.oidcClient = new OidcClient(properties)
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
    String idCardInitUrl
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
    @Lazy fullIdCardInitUrl = "${nodeProtocol}://${nodeHost}${nodePortCheck()}${idCardInitUrl}"
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
    @Lazy fullEidasCallbackUrl = "${protocol}://${host}${portCheck()}${eidasCallbackUrl}"
    @Lazy fullAuthLegalInitUrl = "${protocol}://${host}${portCheck()}${authLegalInitUrl}"
    @Lazy fullAuthLegalPersonUrl = "${protocol}://${host}${portCheck()}${authLegalPersonUrl}"
    @Lazy fullAuthLegalConfirmUrl = "${protocol}://${host}${portCheck()}${authLegalConfirmUrl}"
    @Lazy baseUrl = "${protocol}://${host}${portCheck()}"

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
        this.idCardInitUrl = properties."loginservice.idCardInitUrl"
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
    String port
    String protocol
    String authenticationRequestUrl
    String jwksUrl
    String configurationUrl
    HashMap <String, String> cookies

    @Lazy fullAuthenticationRequestUrl = "${protocol}://${host}${portCheck()}${authenticationRequestUrl}"
    @Lazy fullJwksUrl = "${protocol}://${host}${portCheck()}${jwksUrl}"
    @Lazy fullConfigurationUrl = "${protocol}://${host}${portCheck()}${configurationUrl}"
    @Lazy baseUrl = "${protocol}://${host}${portCheck()}"

    OidcService(Properties properties) {
        this.host = properties."oidcservice.host"
        this.port = properties."oidcservice.port"
        this.protocol = properties."oidcservice.protocol"
        this.authenticationRequestUrl = properties."oidcservice.authenticationRequestUrl"
        this.jwksUrl = properties."oidcservice.jwksUrl"
        this.configurationUrl = properties."oidcservice.configurationUrl"
        this.cookies = new HashMap<String, String>()
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
    class OidcClient {
        String host
        String port
        String protocol
        String responseUrl
        String requestUrl
        String clientId
        String clientSecret
        HashMap <String, String> cookies

        @Lazy fullResponseUrl = "${protocol}://${host}${portCheck()}${responseUrl}"

        OidcClient(Properties properties) {
            this.host = properties."oidcclient.host"
            this.port = properties."oidcclient.port"
            this.protocol = properties."oidcclient.protocol"
            this.responseUrl = properties."oidcclient.responseUrl"
            this.clientId = properties."oidcclient.clientId"
            this.clientSecret = properties."oidcclient.secret"
            this.cookies = new HashMap<String, String>()
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

