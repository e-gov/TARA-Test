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
    String authAcceptUrlUrl
    String consentUrl

    @Lazy fullInitUrl = "${protocol}://${host}${portCheck()}${initUrl}"
    @Lazy fullMidInitUrl = "${protocol}://${host}${portCheck()}${midInitUrl}"
    @Lazy fullMidPollUrl = "${protocol}://${host}${portCheck()}${midPollUrl}"
    @Lazy fullMidCancelUrl = "${protocol}://${host}${portCheck()}${midCancelUrl}"
    @Lazy fullauthAcceptUrl = "${protocol}://${host}${portCheck()}${authAcceptUrlUrl}"
    @Lazy fullConsentUrl = "${protocol}://${host}${portCheck()}${consentUrl}"

    LoginService(Properties properties) {
        this.host = properties."loginservice.host"
        this.port = properties."loginservice.port"
        this.protocol = properties."loginservice.protocol"
        this.initUrl = properties."loginservice.initUrl"
        this.midInitUrl = properties."loginservice.midInitUrl"
        this.midPollUrl = properties."loginservice.midPollUrl"
        this.midCancelUrl = properties."loginservice.midCancelUrl"
        this.authAcceptUrlUrl = properties."loginservice.authAcceptUrl"
        this.consentUrl = properties."loginservice.consentUrl"
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