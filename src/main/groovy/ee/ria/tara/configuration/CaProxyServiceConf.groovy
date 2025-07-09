package ee.ria.tara.configuration

import org.aeonbits.owner.Config

interface CaProxyServiceConf extends Config {
    String protocol()

    String host()

    String port()

    String consentUrl()
}
