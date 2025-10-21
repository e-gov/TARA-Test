package ee.ria.tara.configuration

import org.aeonbits.owner.Config

interface InproxyServiceConf extends Config {
    String host()

    String port()

    String protocol()
}
