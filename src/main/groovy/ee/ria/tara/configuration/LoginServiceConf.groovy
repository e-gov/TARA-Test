package ee.ria.tara.configuration

import org.aeonbits.owner.Config
import org.aeonbits.owner.Config.Key

interface LoginServiceConf extends Config {
    String protocol()

    String host()

    String port()

    @Key("node.protocol")
    String nodeProtocol()

    @Key("node.host")
    String nodeHost()

    @Key("node.port")
    String nodePort()

    String initUrl()

    String midInitUrl()

    String midPollUrl()

    String midCancelUrl()

    String webEidInitUrl()

    String webEidLoginUrl()

    String sidInitUrl()

    String sidPollUrl()

    String sidCancelUrl()

    String authAcceptUrl()

    String authRejectUrl()

    String errorUrl()

    String eidasInitUrl()

    String eidasCallbackUrl()

    String authLegalInitUrl()

    String authLegalPersonUrl()

    String authLegalConfirmUrl()

    String consentUrl()

    String consentConfirmUrl()

    String heartbeatUrl()

    @Key("id.username")
    String idUsername()

    @Key("id.password")
    String idPassword()
}
