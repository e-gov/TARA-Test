package ee.ria.tara.admin

import ee.ria.tara.Flow
import ee.ria.tara.TaraAdminSteps
import ee.ria.tara.TaraSpecification
import ee.ria.tara.model.Client
import ee.ria.tara.model.Institution
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

    @Feature("TARA_MGMT")
    def "Register new client succeeds"() {
        given:
        Institution institution = TaraAdminSteps.createInstitutionSetAssignedFields(flow)
        Client client = Client.clientWithDefaultValues(institution)

        when:
        TaraAdminSteps.createClient(flow, client)

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
        scope << ["openid", "idcard", "mid", "smartid", "eidas", "eidasonly", "eidas:country:*", "email", "phone"]
    }

    @Feature("TARA_MGMT")
    def "Register client with existing 'client id' fails"() {
        given:
        Institution institution = TaraAdminSteps.createInstitutionSetAssignedFields(flow)
        Client client = TaraAdminSteps.createClientSetAssignedFields(flow, institution)
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
        Client client = TaraAdminSteps.createClientSetAssignedFields(flow, institution)

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
        Client client = TaraAdminSteps.createClientSetAssignedFields(flow, institution)
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
        Client client = TaraAdminSteps.createClientSetAssignedFields(flow, institution)

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
        condition                                       | mutation                                                || errorMessage
        "with 21 symbol shortname and GSM-7 characters" | { c -> c.clientShortName.en = "s.name ÜПÖ characters" } || "Klientrakenduse lühinimetuse lubatud pikkus on kuni 40 tähemärki. Kui lühinimetus sisaldab GSM-7 standardi väliseid tähemärke (nt 'õ', 'š', 'ž' või kirillitsat), on lubatud pikkus kuni 20 tähemärki."
        "without 'allowed ip addresses'"                | { c -> c.tokenRequestAllowedIpAddresses.clear() }       || "Vähemalt 1 identsustõendipäringu lubatud IP aadress peab olema defineeritud."
        "without 'scope'"                               | { c -> c.scope.clear() }                                || "Vähemalt 1 skoop peab olema valitud."
        "with incorrect 'eIDAS RequesterID'"            | { c -> c.eidasRequesterId = "1234567890" }              || "eIDAS RequesterID peab olema korrektne URI."
        "without 'eIDAS RequesterID'"                   | { c -> c.eidasRequesterId = null }                      || "eIDAS RequesterID on kohustuslik."
//        "without 'Token endpoint auth method'"             | { c -> c.tokenEndpointAuthMethod = null }  || //incorrect error message "must not be null"
        "without 'client id'"                           | { c -> c.clientId = null }                              || "Klientrakenduse id on puudu."
        // although it's no possible to create client without 'institution name', it's possible to create client by providing incorrect 'institution name'
        "without 'institution name'"                    | { c -> c.institutionMetainfo.name = null }              || "Asutuse nimi peab olema täidetud."
        "without 'institution registry code'"           | { c -> c.institutionMetainfo.registryCode = null }      || "Asutus peab olema valitud."
//        "without 'institution type'"                       | { c -> c.institutionMetainfo.type = null }  || //incorrect error message "must not be null"
    }

    def cleanupSpec() {
        Flow cleanupFlow = new Flow()
        cleanupFlow.cookieFilter = new CookieFilter()
        TaraAdminSteps.taraAdminLoginDefaultUser(cleanupFlow)
        TaraAdminSteps.deleteInstitutionWithClients(cleanupFlow, sharedInstitution)
    }
}
