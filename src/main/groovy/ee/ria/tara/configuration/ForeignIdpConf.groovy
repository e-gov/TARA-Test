package ee.ria.tara.configuration

import org.aeonbits.owner.Config

interface ForeignIdpConf extends Config {
    String protocol()

    String host()

    String port()

    String responseUrl()
}
