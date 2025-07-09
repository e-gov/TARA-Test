package ee.ria.tara.configuration

import org.aeonbits.owner.Config

interface OidcClientConf extends Config {

    String protocol()

    String host()

    String port()

    String responseUrl()

    String clientId()

    String secret()
}
