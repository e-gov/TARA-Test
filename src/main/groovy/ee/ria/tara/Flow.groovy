package ee.ria.tara

import groovy.transform.Canonical
import io.restassured.filter.cookie.CookieFilter

@Canonical
class Flow {
    Properties properties
    OidcService oidcService
    LoginService loginService
    OidcClient oidcClient
    CookieFilter cookieFilter
    String sessionId
    String loginChallenge

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
    @Lazy fullAuthAcceptUrl = "${protocol}://${host}${portCheck()}${authAcceptUrl}"
    @Lazy fullAuthRejectUrl = "${protocol}://${host}${portCheck()}${authRejectUrl}"
    @Lazy fullConsentUrl = "${protocol}://${host}${portCheck()}${consentUrl}"
    @Lazy fullConsenConfirmUrl = "${protocol}://${host}${portCheck()}${consentConfirmUrl}"
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
    HashMap <String, String> cookies

    @Lazy fullAuthenticationRequestUrl = "${protocol}://${host}${portCheck()}${authenticationRequestUrl}"
    @Lazy baseUrl = "${protocol}://${host}${portCheck()}"

    OidcService(Properties properties) {
        this.host = properties."oidcservice.host"
        this.port = properties."oidcservice.port"
        this.protocol = properties."oidcservice.protocol"
        this.authenticationRequestUrl = properties."oidcservice.authenticationRequestUrl"
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
        HashMap <String, String> cookies

        @Lazy fullResponseUrl = "${protocol}://${host}:${port}${responseUrl}"
        @Lazy fullRequestUrl = "${protocol}://${host}:${port}${requestUrl}"

        OidcClient(Properties properties) {
            this.host = properties."oidcclient.host"
            this.port = properties."oidcclient.port"
            this.protocol = properties."oidcclient.protocol"
            this.responseUrl = properties."oidcclient.responseUrl"
            this.requestUrl = properties."oidcclient.requestUrl"
            this.clientId = properties."oidcclient.clientId"
            this.cookies = new HashMap<String, String>()
        }

}