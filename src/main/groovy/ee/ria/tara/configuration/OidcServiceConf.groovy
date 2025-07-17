package ee.ria.tara.configuration

import org.aeonbits.owner.Config

interface OidcServiceConf extends Config {
    String protocol()

    String host()

    String port()

    String authenticationRequestUrl()

    String authorizationUrl()

    String configurationUrl()

    String jwksUrl()
}
