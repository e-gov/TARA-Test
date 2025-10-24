package ee.ria.tara.configuration

import org.aeonbits.owner.Config

interface DemoClientConf extends Config {
    String protocol()

    String host()

    String port()
}
