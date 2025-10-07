package ee.ria.tara


import ee.ria.tara.model.Client
import ee.ria.tara.model.Institution
import io.qameta.allure.Step
import io.restassured.response.Response
import org.apache.http.HttpStatus

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.notNullValue

class TaraAdminSteps {

    @Step("Authenticate as Tara Admin")
    static void taraAdminLogin(Flow flow, String username, String password) {
        Map credentialsMap = [
                "username": username,
                "password": password]
        flow.taraAdminService.xsrfToken = whoAmIRequest(flow, false).getCookie("__Host-XSRF-TOKEN")
        Response loginResponse = TaraAdminRequests.postRequest(flow,
                flow.taraAdminService.fullBaseUrl + "/login", credentialsMap)
        assertThat("Correct HTTP status code", loginResponse.statusCode, is(HttpStatus.SC_OK))
        assertThat("No error alerts", loginResponse.jsonPath().get("error"), is(null))
    }

    @Step("Authenticate as Tara Admin default user")
    static void taraAdminLoginDefaultUser(Flow flow) {
        taraAdminLogin(flow, flow.taraAdminService.username, flow.taraAdminService.password)
    }

    @Step("Who am I request")
    static Response whoAmIRequest(Flow flow, boolean checkStatusCode = true) {
        Response response = Requests.followRedirect(flow, flow.taraAdminService.fullBaseUrl + "/whoami")

        if (checkStatusCode) assertThat("Correct HTTP status code", response.statusCode, is(HttpStatus.SC_OK))

        return response
    }

    static Response tryDeleteInstitution(Flow flow, Institution institution) {
        tryDeleteInstitution(flow, institution.registryCode)
    }

    static Response tryDeleteInstitution(Flow flow, String registryCode) {
        TaraAdminRequests.deleteRequest(flow, "${flow.taraAdminService.fullBaseUrl}/institutions/${registryCode}")
    }

    static Response deleteInstitution(Flow flow, Institution institution) {
        deleteInstitution(flow, institution.registryCode)
    }

    @Step("Delete institution")
    static Response deleteInstitution(Flow flow, String registryCode) {
        tryDeleteInstitution(flow, registryCode)
                .then()
                .statusCode(HttpStatus.SC_OK)
                .extract()
                .response()
    }

    static Response tryCreateInstitution(Flow flow, Institution institution) {
        TaraAdminRequests.postRequest(flow, flow.taraAdminService.fullBaseUrl + "/institutions", institution)
    }

    @Step("Create institution")
    static Response createInstitution(Flow flow, Institution institution) {
        tryCreateInstitution(flow, institution)
                .then()
                .statusCode(HttpStatus.SC_OK)
                .extract()
                .response()
    }

    static Institution createInstitutionSetAssignedFields(Flow flow) {
        createInstitutionSetAssignedFields(flow, Institution.institutionWithDefaultValues())
    }

    @Step("Create institution and assign server-generated fields")
    static Institution createInstitutionSetAssignedFields(Flow flow, Institution institution) {
        createInstitution(flow, institution)
        institution.sync(getInstitution(flow, institution))
        return institution
    }

    @Step("Get institution")
    static Institution getInstitution(Flow flow, Institution institution) {
        Institution foundInstitution = getAllInstitutions(flow).find { it == institution }
        assertThat("Institution '${institution.registryCode}' not found in list.", foundInstitution, is(notNullValue()))
        return foundInstitution
    }

    static Response tryCreateClient(Flow flow, Client client) {
        TaraAdminRequests.postRequest(flow,
                flow.taraAdminService.fullBaseUrl + "/institutions/${client.institution.registryCode}/clients", client)
    }

    @Step("Create client")
    static Response createClient(Flow flow, Client client) {
        tryCreateClient(flow, client)
                .then()
                .statusCode(HttpStatus.SC_OK)
                .extract()
                .response()
    }

    static createClientSetAssignedFields(Flow flow, Institution institution) {
        Client client = Client.clientWithDefaultValues(institution)
        institution.clients.add(client)
        createClientSetAssignedFields(flow, client)
    }

    @Step("Create client and assign server-generated fields")
    static createClientSetAssignedFields(Flow flow, Client client) {
        createClient(flow, client)
        client.institution.clientIds = client.institution.clients*.clientId
        client.sync(getClient(flow, client))
        return client
    }

    @Step("Get client")
    static def getClient(Flow flow, Client client) {
        Client foundIClient = getAllClients(flow).find { it == client }
        assertThat("Institution '${client.clientId}' not found in list.", foundIClient, is(notNullValue()))
        return foundIClient
    }

    @Step("Get all institutions")
    static List<Institution> getAllInstitutions(Flow flow) {
        Response response = TaraAdminRequests.getRequest(flow, flow.taraAdminService.fullBaseUrl + "/institutions")
        assertThat("Correct HTTP status code", response.statusCode, is(HttpStatus.SC_OK))
        return response.jsonPath().getList("\$", Institution)
    }

    @Step("Get all clients")
    static List<Client> getAllClients(Flow flow) {
        Response response = TaraAdminRequests.getRequest(flow, flow.taraAdminService.fullBaseUrl + "/clients")
        assertThat("Correct HTTP status code", response.statusCode, is(HttpStatus.SC_OK))
        return response.jsonPath().getList("\$", Client)
    }

    @Step("Get all clients of institution")
    static List<Client> getAllClientsOfInstitution(Flow flow, String registryCode) {
        Response response = TaraAdminRequests.getRequest(flow, flow.taraAdminService.fullBaseUrl + "/institutions/${registryCode}/clients")
        assertThat("Correct HTTP status code", response.statusCode, is(HttpStatus.SC_OK))
        return response.jsonPath().getList("\$", Client)
    }

    @Step("Delete client")
    static Response deleteClient(Flow flow, Client client) {
        TaraAdminRequests.deleteRequest(flow, "${flow.taraAdminService.fullBaseUrl}/institutions/${client.institutionMetainfo.registryCode}/clients/${client.clientId}")
                .then()
                .statusCode(HttpStatus.SC_OK)
                .extract()
                .response()
    }

    @Step("Delete institution and related clients")
    static deleteInstitutionWithClients(Flow flow, Institution institution) {
        getAllClientsOfInstitution(flow, institution.registryCode).each { client ->
            deleteClient(flow, client)
        }
        deleteInstitution(flow, institution)
    }

    @Step("Verify client and institution")
    static boolean verifyClientAndInstitution(Flow flow, Client client) {

        def institutionClients = getAllClientsOfInstitution(flow, client.institution.registryCode)
        assertThat("Correct amount of registered clients", institutionClients.size(), is(client.institution.clientIds.size()))

        Client matchingClient = getClient(flow, client)
        assertThat("Created client data matches registered client", matchingClient != null)
        assertThat(client.id, is(matchingClient.id))
        assertThat(client.createdAt, is(matchingClient.createdAt))
        assertThat(client.updatedAt, is(matchingClient.updatedAt))

        Institution matchingInstitution = getInstitution(flow, client.institution)
        assertThat("Created institution data matches registered institution", matchingInstitution != null)
        assertThat(client.institution.createdAt, is(matchingInstitution.createdAt))
        assertThat(client.institution.updatedAt, is(matchingInstitution.updatedAt))
        return true
    }

    @Step("Verify institution")
    static boolean verifyInstitution(Flow flow, Institution institution) {
        Institution registeredInstitution = getInstitution(flow, institution)
        assertThat("Institutions data does not match", institution, is(registeredInstitution))
        assertThat("CreatedAt timestamp does not match", institution.createdAt, is(registeredInstitution.createdAt))
        assertThat("UpdatedAt timestamp does not match", institution.updatedAt, is(registeredInstitution.updatedAt))
        def institutionClients = getAllClientsOfInstitution(flow, institution.registryCode)
        assertThat("Mismatch in number of registered clients", institutionClients.size(), is(institution.clientIds.size()))
        return true
    }

    @Step("Verify client")
    static boolean verifyClient(Flow flow, Client client) {
        Client registeredClient = getClient(flow, client)
        assertThat("Client data does not match", client, is(registeredClient))
        assertThat("Id does not match", client.id, is(registeredClient.id))
        assertThat("CreatedAt timestamp does not match", client.createdAt, is(registeredClient.createdAt))
        assertThat("CreatedAt timestamp does not match", client.updatedAt, is(registeredClient.updatedAt))
        return true
    }
}
