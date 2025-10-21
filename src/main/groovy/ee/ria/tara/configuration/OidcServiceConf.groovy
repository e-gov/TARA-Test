package ee.ria.tara.configuration

import org.aeonbits.owner.Config
import org.aeonbits.owner.Config.Key

interface OidcServiceConf extends Config {
    String protocol()

    String host()

    String port()

    @Key("node.protocol")
    String nodeProtocol()

    @Key("node.host")
    String nodeHost()

    @Key("node.port")
    String nodePort()

    String authenticationRequestUrl()

    String authorizationUrl()

    String configurationUrl()

    String jwksUrl()
}
