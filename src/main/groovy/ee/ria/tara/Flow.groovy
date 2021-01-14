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
    CookieFilter cookieFilter
    String sessionId
    String loginChallenge

    String state
    String nonce
    JWKSet jwkSet
    JsonPath openIdServiceConfiguration

    Flow(Properties properties) {
        this.properties = properties
        this.loginService = new LoginService(properties)
        this.oidcService = new OidcService(properties)
        this.oidcClient = new OidcClient(properties)
    }
}

@Canonical
class LoginService {
    String host
    String port
    String protocol
    String initUrl
    String midInitUrl
    String midPollUrl
    String midCancelUrl
    String idCardInitUrl
    String authAcceptUrl
    String authRejectUrl
    String consentUrl
    String consentConfirmUrl
    String heartbeatUrl
    String authLegalInitUrl
    String authLegalPersonUrl
    String authLegalConfirmUrl

    @Lazy fullInitUrl = "${protocol}://${host}${portCheck()}${initUrl}"
    @Lazy fullMidInitUrl = "${protocol}://${host}${portCheck()}${midInitUrl}"
    @Lazy fullMidPollUrl = "${protocol}://${host}${portCheck()}${midPollUrl}"
    @Lazy fullMidCancelUrl = "${protocol}://${host}${portCheck()}${midCancelUrl}"
    @Lazy fullIdCardInitUrl = "${protocol}://${host}${portCheck()}${idCardInitUrl}"
    @Lazy fullAuthAcceptUrl = "${protocol}://${host}${portCheck()}${authAcceptUrl}"
    @Lazy fullAuthRejectUrl = "${protocol}://${host}${portCheck()}${authRejectUrl}"
    @Lazy fullConsentUrl = "${protocol}://${host}${portCheck()}${consentUrl}"
    @Lazy fullConsentConfirmUrl = "${protocol}://${host}${portCheck()}${consentConfirmUrl}"
    @Lazy fullHeartbeatUrl = "${protocol}://${host}${portCheck()}${heartbeatUrl}"
    @Lazy fullAuthLegalInitUrl = "${protocol}://${host}${portCheck()}${authLegalInitUrl}"
    @Lazy fullAuthLegalPersonUrl = "${protocol}://${host}${portCheck()}${authLegalPersonUrl}"
    @Lazy fullAuthLegalConfirmUrl = "${protocol}://${host}${portCheck()}${authLegalConfirmUrl}"
    @Lazy baseUrl = "${protocol}://${host}${portCheck()}"

    LoginService(Properties properties) {
        this.host = properties."loginservice.host"
        this.port = properties."loginservice.port"
        this.protocol = properties."loginservice.protocol"
        this.initUrl = properties."loginservice.initUrl"
        this.midInitUrl = properties."loginservice.midInitUrl"
        this.midPollUrl = properties."loginservice.midPollUrl"
        this.midCancelUrl = properties."loginservice.midCancelUrl"
        this.idCardInitUrl = properties."loginservice.idCardInitUrl"
        this.authAcceptUrl = properties."loginservice.authAcceptUrl"
        this.authRejectUrl = properties."loginservice.authRejectUrl"
        this.consentUrl = properties."loginservice.consentUrl"
        this.consentConfirmUrl = properties."loginservice.consentConfirmUrl"
        this.heartbeatUrl = properties."loginservice.heartbeatUrl"
        this.authLegalInitUrl = properties."loginservice.authLegalInitUrl"
        this.authLegalPersonUrl = properties."loginservice.authLegalPersonUrl"
        this.authLegalConfirmUrl = properties."loginservice.authLegalConfirmUrl"
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
        @Lazy fullRequestUrl = "${protocol}://${host}${portCheck()}${requestUrl}"

        OidcClient(Properties properties) {
            this.host = properties."oidcclient.host"
            this.port = properties."oidcclient.port"
            this.protocol = properties."oidcclient.protocol"
            this.responseUrl = properties."oidcclient.responseUrl"
            this.requestUrl = properties."oidcclient.requestUrl"
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