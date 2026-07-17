package ee.ria.tara.configuration

import org.aeonbits.owner.Config

interface EidTestPkiServiceConf extends Config {
    String managementApiUrl()
}
