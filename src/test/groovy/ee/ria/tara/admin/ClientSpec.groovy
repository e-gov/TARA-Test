package ee.ria.tara.admin

import ee.ria.tara.Flow
import ee.ria.tara.TaraAdminSteps
import ee.ria.tara.TaraSpecification
import ee.ria.tara.model.Client
import ee.ria.tara.model.ClientContact
import ee.ria.tara.model.ClientName
import ee.ria.tara.model.ClientSecretExportSettings
import ee.ria.tara.model.ClientShortName
import ee.ria.tara.model.Institution
import ee.ria.tara.model.InstitutionMetainfo
import ee.ria.tara.model.MidSettings
import ee.ria.tara.model.SmartidSettings
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.http.HttpStatus
import spock.lang.Ignore
import spock.lang.Issue
import spock.lang.Shared

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*

class ClientSpec extends TaraSpecification {

    @Shared
    Institution sharedInstitution

    def setupSpec() {
        Flow setupFlow = new Flow()
        setupFlow.cookieFilter = new CookieFilter()
        sharedInstitution = Institution.institutionWithDefaultValues()
        TaraAdminSteps.taraAdminLoginDefaultUser(setupFlow)
        TaraAdminSteps.createInstitution(setupFlow, sharedInstitution)
    }

    def setup() {
        flow.cookieFilter = new CookieFilter()
        TaraAdminSteps.taraAdminLoginDefaultUser(flow)
    }

    def cleanupSpec() {
        Flow cleanupFlow = new Flow()
        cleanupFlow.cookieFilter = new CookieFilter()
        TaraAdminSteps.taraAdminLoginDefaultUser(cleanupFlow)
        TaraAdminSteps.deleteInstitutionWithClients(cleanupFlow, sharedInstitution)
    }

    @Feature("TARA_MGMT")
    def "Register new client succeeds"() {
        given:
        Institution institution = TaraAdminSteps.createInstitutionSetAssignedFields(flow)
        Client client = Client.clientWithDefaultValues(institution)

        when:
        TaraAdminSteps.createClient(flow, client)
        client.applyServerDefaults()

        then:
        Client registeredClient = TaraAdminSteps.getClient(flow, client)
        assertThat("Client data does not match", registeredClient, is(client))
        assertThat(registeredClient.id, is(notNullValue()))
        assertThat(registeredClient.createdAt, is(notNullValue()))
        assertThat(registeredClient.updatedAt, is(notNullValue()))

        cleanup:
        TaraAdminSteps.deleteInstitutionWithClients(flow, institution)
    }

    @Feature("TARA_MGMT")
    def "Register client with minimum required fields"() {
        given:
        Institution institution = TaraAdminSteps.createInstitutionSetAssignedFields(flow)
        Client client = clientWithMinimumRequiredFields(institution)

        when:
        TaraAdminSteps.createClientSetAssignedFields(flow, client)

        then:
        TaraAdminSteps.verifyClient(flow, client)

        cleanup:
        TaraAdminSteps.deleteInstitutionWithClients(flow, institution)
    }

    @Feature("TARA_MGMT")
    def "Register client with all allowed fields"() {
        given:
        Institution institution = TaraAdminSteps.createInstitutionSetAssignedFields(flow)
        Client client = clientWithAllAllowedFields(institution)

        when:
        TaraAdminSteps.createClientSetAssignedFields(flow, client)

        then:
        TaraAdminSteps.verifyClientAndInstitution(flow, client)

        cleanup:
        TaraAdminSteps.deleteInstitutionWithClients(flow, institution)
    }

    @Feature("TARA_MGMT")
    def "Update client with minimum required fields by changing minimum fields required for registration, verify data complete"() {
        given:
        Institution institution = TaraAdminSteps.createInstitutionSetAssignedFields(flow)
        Client client = clientWithMinimumRequiredFields(institution)
        TaraAdminSteps.createClientSetAssignedFields(flow, client)

        when:
        client.clientShortName = new ClientShortName()
        client.redirectUris = ["https://example24.com/edasi?=1243"]
        client.tokenRequestAllowedIpAddresses = ["10.0.0.1"]
        client.scope = ["openid"]

        TaraAdminSteps.updateClientSetAssignedFields(flow, client)

        then:
        TaraAdminSteps.verifyClient(flow, client)

        cleanup:
        TaraAdminSteps.deleteInstitutionWithClients(flow, institution)
    }

    @Feature("TARA_MGMT")
    def "Update client with minimum required fields by changing all allowed fields, verify data complete"() {
        given:
        Institution institution = TaraAdminSteps.createInstitutionSetAssignedFields(flow)
        Client client = clientWithMinimumRequiredFields(institution)
        TaraAdminSteps.createClientSetAssignedFields(flow, client)

        when:
        Institution newInstitution = TaraAdminSteps.createInstitutionSetAssignedFields(flow)
        Client updatedClient = clientWithAllAllowedFields(newInstitution)
        updatedClient.id = client.id
        updatedClient.createdAt = client.createdAt
        updatedClient.clientId = client.clientId
        updatedClient.eidasRequesterId = client.eidasRequesterId
        updatedClient.institution.clients.add(updatedClient)

        TaraAdminSteps.updateClientSetAssignedFields(flow, updatedClient)

        then:
        TaraAdminSteps.verifyClientAndInstitution(flow, updatedClient)

        cleanup:
        TaraAdminSteps.deleteInstitutionWithClients(flow, institution)
        TaraAdminSteps.deleteInstitutionWithClients(flow, newInstitution)
    }

    @Feature("TARA_MGMT")
    def "Update client with all allowed fields by changing all allowed fields, verify data complete"() {
        given:
        Institution institution = TaraAdminSteps.createInstitutionSetAssignedFields(flow)
        Client client = clientWithAllAllowedFields(institution)
        TaraAdminSteps.createClientSetAssignedFields(flow, client)

        when:
        Institution newInstitution = TaraAdminSteps.createInstitutionSetAssignedFields(flow)
        Client updatedClient = clientWithAllAllowedFields(newInstitution)

        updatedClient.id = client.id
        updatedClient.createdAt = client.createdAt
        updatedClient.clientId = client.clientId
        updatedClient.eidasRequesterId = client.eidasRequesterId
        updatedClient.institution.clients.add(updatedClient)

        updatedClient.clientName.et = modifyData(client.clientName.et)
        updatedClient.clientName.en = modifyData(client.clientName.en)
        updatedClient.clientName.ru = modifyData(client.clientName.ru)
        updatedClient.clientShortName.en = modifyData(client.clientShortName.en)
        updatedClient.clientShortName.et = modifyData(client.clientShortName.et)
        updatedClient.clientShortName.ru = modifyData(client.clientShortName.ru)

        updatedClient.redirectUris = modifyData(client.redirectUris)

        updatedClient.tokenRequestAllowedIpAddresses.remove("0.0.0.0/0")
        updatedClient.tokenRequestAllowedIpAddresses.add("81.0.0.0/0")

        updatedClient.scope = ["openid", "idcard", "eidasonly", "eidas:country:*", "email"]

        updatedClient.description = modifyData(client.description)

        updatedClient.clientUrl = modifyData(client.clientUrl)

        updatedClient.infoNotificationEmails = modifyData(client.infoNotificationEmails)

        updatedClient.slaNotificationEmails = modifyData(client.slaNotificationEmails)

        updatedClient.isUserConsentRequired = modifyData(client.isUserConsentRequired)

        updatedClient.midSettings.relyingPartyUUID = UUID.randomUUID()
        updatedClient.midSettings.relyingPartyName = modifyData(client.midSettings.relyingPartyName)

        updatedClient.smartidSettings.relyingPartyUUID = UUID.randomUUID()
        updatedClient.smartidSettings.relyingPartyName = modifyData(client.smartidSettings.relyingPartyName)
        updatedClient.smartidSettings.shouldUseAdditionalVerificationCodeCheck = modifyData(client.smartidSettings.shouldUseAdditionalVerificationCodeCheck)

        updatedClient.minimumAcrValue = modifyData(client.minimumAcrValue)

        updatedClient.clientContacts = modifyData(client.clientContacts)

        TaraAdminSteps.updateClientSetAssignedFields(flow, updatedClient)

        then:
        TaraAdminSteps.verifyClientAndInstitution(flow, updatedClient)

        cleanup:
        TaraAdminSteps.deleteInstitutionWithClients(flow, institution)
        TaraAdminSteps.deleteInstitutionWithClients(flow, newInstitution)
    }

    @Issue("Test does not work in local environment.")
    @Feature("TARA_MGMT")
    def "Client registration succeeds when sending secret fails"() {
        given:
        Institution institution = TaraAdminSteps.createInstitutionSetAssignedFields(flow)
        Client client = Client.clientWithDefaultValues(institution)
        client.clientSecretExportSettings = new ClientSecretExportSettings(
                recipientIdCode: "38001085718",
                recipientEmail: "invalid@invalidmail.com"
        )

        when:
        Response response = TaraAdminSteps.tryCreateClient(flow, client)

        then:
        response.then()
                .statusCode(500)
                .body(equalTo("Klientrakendus salvestatud, aga saladuse saatmine emailiga ebaõnnestus, proovi mõne aja pärast uuesti."))

        TaraAdminSteps.assignServerGeneratedFields(flow, client)
        TaraAdminSteps.verifyClient(flow, client)

        cleanup:
        TaraAdminSteps.deleteInstitutionWithClients(flow, institution)
    }

    @Issue("Test does not work in local environment.")
    @Feature("TARA_MGMT")
    def "Sending secret fails for already created client and does not affect client data"() {
        given:
        Institution institution = TaraAdminSteps.createInstitutionSetAssignedFields(flow)
        Client client = Client.clientWithDefaultValues(institution)
        TaraAdminSteps.createClientSetAssignedFields(flow, client)

        when:
        client.clientSecretExportSettings = new ClientSecretExportSettings(
                recipientIdCode: "38001085718",
                recipientEmail: "invalid@invalidmail.com"
        )
        Response response = TaraAdminSteps.tryUpdateClient(flow, client)

        then:
        response.then()
                .statusCode(500)
                .body(equalTo("Klientrakendus salvestatud, aga saladuse saatmine emailiga ebaõnnestus, proovi mõne aja pärast uuesti."))

        TaraAdminSteps.assignServerGeneratedFields(flow, client, ["updatedAt"])
        TaraAdminSteps.verifyClient(flow, client)

        cleanup:
        TaraAdminSteps.deleteInstitutionWithClients(flow, institution)
    }

    @Feature("TARA_MGMT")
    def "Register client with single scope '#scope' succeeds"() {
        given:
        Client client = Client.clientWithDefaultValues(sharedInstitution)
        client.scope = [scope]

        when:
        TaraAdminSteps.createClientSetAssignedFields(flow, client)

        then:
        TaraAdminSteps.verifyClient(flow, client)

        cleanup:
        TaraAdminSteps.deleteClient(flow, client)

        where:
        scope << ["openid", "idcard", "mid", "smartid", "eidas", "eidasonly", "eidas:country:*", "email", "phone", "legalperson"]
    }

    @Feature("TARA_MGMT")
    def "Register client with existing 'client id' fails"() {
        given:
        Institution institution = TaraAdminSteps.createInstitutionSetAssignedFields(flow)
        Client client = TaraAdminSteps.createDefaultClientSetAssignedFields(flow, institution)
        Client newClient = Client.clientWithDefaultValues(institution, client.clientId)

        when:
        Response createClientResponse = TaraAdminSteps.tryCreateClient(flow, newClient)

        then:
        createClientResponse.then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body(equalTo("Selline kliendi ID juba eksisteerib."))

        and:
        TaraAdminSteps.verifyClientAndInstitution(flow, client)

        cleanup:
        TaraAdminSteps.deleteInstitutionWithClients(flow, institution)
    }

    @Feature("TARA_MGMT")
    def "Register client with existing 'id' and 'client id' fails"() {
        given:
        Institution institution = TaraAdminSteps.createInstitutionSetAssignedFields(flow)
        Client client = TaraAdminSteps.createDefaultClientSetAssignedFields(flow, institution)

        Client newClient = Client.clientWithDefaultValues(institution, client.clientId)
        newClient.id = client.id

        when:
        Response createClientResponse = TaraAdminSteps.tryCreateClient(flow, newClient)

        then:
        createClientResponse.then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body(equalTo("OIDC kasutaja juba eksisteerib."))

        and:
        TaraAdminSteps.verifyClientAndInstitution(flow, client)

        cleanup:
        TaraAdminSteps.deleteInstitutionWithClients(flow, institution)
    }

    @Ignore("AUT-2440")
    @Issue("AUT-2440 issue nr1")
    @Feature("TARA_MGMT")
    def "Register client with existing 'id' and different 'client id' fails"() {
        given:
        Institution institution = TaraAdminSteps.createInstitutionSetAssignedFields(flow)
        Client client = TaraAdminSteps.createDefaultClientSetAssignedFields(flow, institution)
        Client newClient = Client.clientWithDefaultValues(institution)
        newClient.id = client.id

        when:
        Response createClientResponse = TaraAdminSteps.tryCreateClient(flow, newClient)

        then:
        createClientResponse.then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body(equalTo("OIDC kasutaja juba eksisteerib."))

        and:
        TaraAdminSteps.verifyClientAndInstitution(flow, client)

        cleanup:
        TaraAdminSteps.deleteInstitutionWithClients(flow, institution)
    }

    @Feature("TARA_MGMT")
    def "Register client with existing 'eIDAS RequesterID' and different 'client id' fails"() {
        given:
        Institution institution = TaraAdminSteps.createInstitutionSetAssignedFields(flow)
        Client client = TaraAdminSteps.createDefaultClientSetAssignedFields(flow, institution)

        Client newClient = Client.clientWithDefaultValues(institution)
        newClient.eidasRequesterId = client.eidasRequesterId

        when:
        Response createClientResponse = TaraAdminSteps.tryCreateClient(flow, newClient)

        then:
        createClientResponse.then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body(equalTo("Sisestatud eIDAS RequesterID on juba kasutusel."))

        and:
        TaraAdminSteps.verifyClientAndInstitution(flow, client)

        cleanup:
        TaraAdminSteps.deleteInstitutionWithClients(flow, institution)
    }

    @Issue("AUT-935")
    @Feature("TARA_MGMT")
    def "Register client '#condition' fails"() {
        given:
        Client client = Client.clientWithDefaultValues(sharedInstitution)
        mutation(client)

        when:
        Response createClientResponse = TaraAdminSteps.tryCreateClient(flow, client)

        then:
        createClientResponse.then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body(equalTo(errorMessage))

        where:
        condition                                       | mutation                                                            || errorMessage
        "with 21 symbol shortname and GSM-7 characters" | { c -> c.clientShortName.en = "s.name ÜПÖ characters" }             || "Klientrakenduse lühinimetuse lubatud pikkus on kuni 40 tähemärki. Kui lühinimetus sisaldab GSM-7 standardi väliseid tähemärke (nt 'õ', 'š', 'ž' või kirillitsat), on lubatud pikkus kuni 20 tähemärki."
        "without 'allowed ip addresses'"                | { c -> c.tokenRequestAllowedIpAddresses.clear() }                   || "Vähemalt 1 identsustõendipäringu lubatud IP aadress peab olema defineeritud."
        "with incorrect 'allowed ip address'"           | { c -> c.tokenRequestAllowedIpAddresses.add("http://192.168.0.1") } || "Kliendi identsustõendipäringu lubatud IP aadresside nimekiri sisaldab ebakorrekselt vormistatud IP aadressi."
        "without 'redirect uris'"                       | { c -> c.redirectUris.clear() }                                     || "Vähemalt 1 tagasisuunamise url peab olema defineeritud."
        "without 'scope'"                               | { c -> c.scope.clear() }                                            || "Vähemalt 1 skoop peab olema valitud."
        "with incorrect 'eIDAS RequesterID'"            | { c -> c.eidasRequesterId = "1234567890" }                          || "eIDAS RequesterID peab olema korrektne URI."
        "without 'eIDAS RequesterID'"                   | { c -> c.eidasRequesterId = null }                                  || "eIDAS RequesterID on kohustuslik."
//        "without 'Token endpoint auth method'"             | { c -> c.tokenEndpointAuthMethod = null }  || //incorrect error message "must not be null"
        "without 'client id'"                           | { c -> c.clientId = null }                                          || "Klientrakenduse id on puudu."
        // although it's no possible to create client without 'institution name', it's possible to create client by providing incorrect 'institution name'
        "without 'institution name'"                    | { c -> c.institutionMetainfo.name = null }                          || "Asutuse nimi peab olema täidetud."
        "without 'institution registry code'"           | { c -> c.institutionMetainfo.registryCode = null }                  || "Asutus peab olema valitud."
//        "without 'institution type'"                       | { c -> c.institutionMetainfo.type = null }  || //incorrect error message "must not be null"
    }

    @Feature("TARA_MGMT")
    def "Update client #field field from #originalValue to #updatedValue"() {
        given:
        Client client = clientWithAllAllowedFields(sharedInstitution)
        client.setProperty(field, originalValue)
        TaraAdminSteps.createClientSetAssignedFields(flow, client)

        when:
        client.setProperty(field, updatedValue)
        TaraAdminSteps.updateClientSetAssignedFields(flow, client)

        then:
        TaraAdminSteps.verifyClient(flow, client)

        cleanup:
        TaraAdminSteps.deleteClient(flow, client)

        where:
        field                   | originalValue                                                        | updatedValue
        "minimumAcrValue"       | "low"                                                                | "substantial"
        "minimumAcrValue"       | "low"                                                                | "high"
        "minimumAcrValue"       | "substantial"                                                        | "low"
        "minimumAcrValue"       | "substantial"                                                        | "high"
        "minimumAcrValue"       | "high"                                                               | "low"
        "minimumAcrValue"       | "high"                                                               | "substantial"

        "isUserConsentRequired" | "true"                                                               | "false"
        "isUserConsentRequired" | "false"                                                              | "true"

        "smartidSettings"       | new SmartidSettings(shouldUseAdditionalVerificationCodeCheck: true)  | new SmartidSettings(shouldUseAdditionalVerificationCodeCheck: false)
        "smartidSettings"       | new SmartidSettings(shouldUseAdditionalVerificationCodeCheck: false) | new SmartidSettings(shouldUseAdditionalVerificationCodeCheck: true)
    }

    static clientWithMinimumRequiredFields(Institution institution) {
        clientWithMinimumRequiredFields(institution, UUID.randomUUID().toString())
    }

    static clientWithMinimumRequiredFields(Institution institution, String clientId) {
        new Client(
                clientId: clientId,
                clientShortName: new ClientShortName(),
                institutionMetainfo: new InstitutionMetainfo(
                        name: institution.name,
                        registryCode: institution.registryCode,
                        type: institution.type,
                ),
                redirectUris: ["https://example24.com/edasi?=1243"],
                tokenRequestAllowedIpAddresses: ["10.0.0.1"],
                tokenEndpointAuthMethod: "client_secret_basic",
                scope: ["idcard"],
                eidasRequesterId: "urn:uuid:" + UUID.randomUUID(),
                institution: institution
        )
    }

    static clientWithAllAllowedFields(Institution institution) {
        clientWithAllAllowedFields(institution, UUID.randomUUID().toString())
    }

    static clientWithAllAllowedFields(Institution institution, String clientId) {
        new Client(
                clientId: clientId,
                clientName: new ClientName(
                        en: "Test client ^&öж1234",
                        et: "Test klient 1111111111111111111111111111",
                        ru: "тестовый клиент ^&öж",
                ),
                clientShortName: new ClientShortName(
                        en: "Tc (short name) 123456789111111111111111",
                        et: "Tk (lühinimi) ^&öжsd",
                        ru: "Т(короткое имя) ^&öж",
                ),
                institutionMetainfo: new InstitutionMetainfo(
                        name: institution.name,
                        registryCode: institution.registryCode,
                        type: institution.type,
                ),
                redirectUris: ["https://www.example.com/edasi", "https://www.example.ee/portal",
                               "https://www.example24.ee", "https://example.ee"],
                tokenRequestAllowedIpAddresses: ["0.0.0.0/0", "::/0", "127.0.0.1", "192.168.0.1/10"],
                tokenEndpointAuthMethod: "client_secret_basic",
                scope: ["idcard", "mid", "smartid", "email", "phone", "legalperson"],
                description: "ÜÖыф#\$%#@^",
                clientUrl: "http://klientrakenduse24.url",
                accessTokenJwtEnabled: false,
                accessTokenAudienceUris: [],
                infoNotificationEmails: ["tehniline@email.com", "Tehniline2@e.ee", "1@2.3"],
                slaNotificationEmails: ["k@2.3", "Katkestus@email.com", "katkestus2@e.ee"],
                isUserConsentRequired: true,
                midSettings: new MidSettings(
                        relyingPartyUUID: UUID.randomUUID(),
                        relyingPartyName: "#%(&@(öüä&ззжызв287)( name"
                ),
                smartidSettings: new SmartidSettings(
                        relyingPartyUUID: UUID.randomUUID(),
                        relyingPartyName: "name#%(&@(öüä&зз жызв287 )(",
                        shouldUseAdditionalVerificationCodeCheck: true
                ),
                minimumAcrValue: "low",
                clientContacts: [
                        new ClientContact(name: "Uuno Udu", email: "uuno@tugi.ee", phone: "+370876543", department: "AIA"),
                        new ClientContact(name: "Tiiu Trepp", email: "tiiu.trepp@tugi.ee", phone: "+37134567", department: "Kollane"),
                        new ClientContact(name: "Tiiu 'üАЫ*", email: "Repp3@t.ee", phone: "55566677", department: "Синий üАЫ&%"),
                        new ClientContact(name: "Tiiu 'üАЫ*2", email: "1epp.1243.sdf@t1234567890.ee", phone: "+371 5123432", department: "Синий üАЫ&%"),
                ],
                eidasRequesterId: "urn:uuid:" + UUID.randomUUID(),

                institution: institution
        )
    }

    static modifyData(String string) {
        if (string.contains("@")) return "MODIFIED_" + string
        else if (string.contains("http")) return string + "/MODIFIED"
        else if (string == "true") return "false"
        else if (string == "false") return "true"
        else if (string == "low" || string == "high") return "substantial"
        else if (string == "substantial") return "low"
        else if (string.matches("[0-9 ]+")) return string.size() >= 5 ? string.substring(0, 3) + "888" : string + "888"
        else if (string.startsWith("+") && string.replace("+", "").matches("[0-9 ]+")) return string.size() >= 8 ? string.substring(0, 5) + "888" : string + "888"
        else if (string.size() <= 10) return string + " MODIFIED"
        else return string.substring(0, string.length() - 9) + " MODIFIED"
    }

    static modifyData(Set set) {
        Set newSet = new HashSet<>()
        set.forEach {
            switch (it) {
                case String -> newSet.add(modifyData(it))
                case ClientContact -> {
                    newSet.add(new ClientContact(
                            name: modifyData(it.name),
                            email: modifyData(it.email),
                            phone: modifyData(it.phone),
                            department: modifyData(it.department)))
                }
            }
        }
        return newSet
    }
}
