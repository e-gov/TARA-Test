package ee.ria.tara.configuration

import org.aeonbits.owner.Config

interface AdminServiceConf extends Config {
    String host()

    String port()

    String protocol()

    String username()

    String password()
}
