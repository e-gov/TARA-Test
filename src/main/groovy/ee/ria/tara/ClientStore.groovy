package ee.ria.tara

import com.fasterxml.jackson.databind.ObjectMapper
import ee.ria.tara.configuration.ConfigHolder
import ee.ria.tara.model.Client

import java.nio.file.Path
import java.nio.file.Paths

class ClientStore {

    @Lazy
    static Client specificProxyService = readClientJson("client-ee-specificproxyservice")

    @Lazy
    static Client mockPublic = readClientJson("client-mock-public")

    @Lazy
    static Client mockPrivate = readClientJson("client-mock-private")

    @Lazy
    static Client mockLegal = readClientJson("client-mock-legal")

    @Lazy
    static Client mockRelyingParty = readClientJson("client-mock-relying-party")

    @Lazy
    static Client mockSecretPost = readClientJson("client-mock-secret-post")

    @Lazy
    static Client mockAcrLow = readClientJson("client-mock-acr-low")

    @Lazy
    static Client mockAcrSubstantial = readClientJson("client-mock-acr-substantial")

    @Lazy
    static Client mockAcrHigh = readClientJson("client-mock-acr-high")

    static Client readClientJson(String fileName) {
        Path filePath = Paths.get(ConfigHolder.testConf.adminSetupPath(), "${fileName}.json")
        return new ObjectMapper().readValue(filePath.toFile(), Client)
    }
}
