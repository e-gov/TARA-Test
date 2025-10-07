package ee.ria.tara.admin

import ee.ria.tara.TaraAdminSteps
import ee.ria.tara.TaraSpecification
import ee.ria.tara.model.Institution
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.commons.lang3.RandomStringUtils
import org.apache.http.HttpStatus
import spock.lang.Issue

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*

class InstitutionSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
        TaraAdminSteps.taraAdminLoginDefaultUser(flow)
    }

    @Feature("TARA_MGMT")
    def "Register new institution succeeds"() {
        given:
        Institution institution = Institution.institutionWithDefaultValues()

        when:
        TaraAdminSteps.createInstitution(flow, institution)

        then:
        Institution registeredInstitution = TaraAdminSteps.getInstitution(flow, institution)
        assertThat("Institutions data does not match", registeredInstitution, is(institution))
        assertThat(registeredInstitution.createdAt, is(notNullValue()))
        assertThat(registeredInstitution.updatedAt, is(notNullValue()))

        cleanup:
        TaraAdminSteps.deleteInstitutionWithClients(flow, institution)
    }


    @Feature("TARA_MGMT")
    def "Register institution with existing 'registry code' fails"() {
        given:
        Institution institution = TaraAdminSteps.createInstitutionSetAssignedFields(flow)
        Institution newInstitution = Institution.institutionWithDefaultValues(institution.registryCode)

        when:
        Response createInstitutionResponse = TaraAdminSteps.tryCreateInstitution(flow, newInstitution)

        then:
        createInstitutionResponse.then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body(equalTo("Sellise registrikoodiga asutus juba eksisteerib."))

        and:
        TaraAdminSteps.verifyInstitution(flow, institution)

        cleanup:
        TaraAdminSteps.deleteInstitutionWithClients(flow, institution)
    }

    @Issue("AUT-2440")
    @Feature("TARA_MGMT")
    def "Delete institution with associated client fails"() {
        given:
        Institution institution = TaraAdminSteps.createInstitutionSetAssignedFields(flow)
        TaraAdminSteps.createClientSetAssignedFields(flow, institution)

        when: "deleting institution witt "
        Response deleteInstitutionResponse = TaraAdminSteps.tryDeleteInstitution(flow, institution)

        then:
        deleteInstitutionResponse.then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
//                .body(equalTo("Asutust ei saa kustutada, kui sellel on seotud kliente.")) // AUT-2440
                .body(equalTo("Asutust ei saa kustutada, kui sellel on seotud kliente.."))

        and:
        TaraAdminSteps.verifyInstitution(flow, institution)

        cleanup:
        TaraAdminSteps.deleteInstitutionWithClients(flow, institution)
    }

    @Issue("AUT-935")
    @Feature("TARA_MGMT")
    def "Register institution '#condition' fails"() {
        given:
        def institution = Institution.institutionWithDefaultValues()
        mutation(institution)

        when:
        Response createInstitutionResponse = TaraAdminSteps.tryCreateInstitution(flow, institution)

        then:
        createInstitutionResponse.then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body(equalTo(errorMessage))

        where:
        condition                                | mutation                                                    || errorMessage
        "with name length less than required"    | { i -> i.name = "AB" }                                      || "Asutuse nimi peab olema 3 kuni 150 tähemärki."
        "with name length greater than required" | { i -> i.name = RandomStringUtils.random(151, true, true) } || "Asutuse nimi peab olema 3 kuni 150 tähemärki."
        "without name"                           | { i -> i.name = null }                                      || "Asutuse nimi on puudu."
        "without 'registry code'"                | { i -> i.registryCode = null }                              || "Registrikood on puudu."
//        "with 'registry code' length less than required" | { i -> i.registryCode = "12" }                              || "Registrikood peab koosnema vähemalt 3 numbrist." // AUT-2440
//        "with 'registry code' length greater than allowed" | { i -> i.registryCode = RandomStringUtils.random(300, false, true) } || //incorrect message "Sellise registrikoodiga asutus juba eksisteerib."
//        "with 'registry code' containing letters"          | { i -> i.registryCode = "12345a" } || //incorrect message "Registrikood peab koosnema vähemalt 3 numbrist.."
        "without 'type'"                         | { i -> i.type.type = null }                                 || "Asutuse tüüp on puudu."
        "without 'address'"                      | { i -> i.address = null }                                   || "Aadress on puudu."
//        "with 'address' length greater than allowed"       | { i -> i.address = RandomStringUtils.random(300, true, true) } || //incorrect message "Sellise registrikoodiga asutus juba eksisteerib."
        "without 'phone'"                        | { i -> i.phone = null }                                     || "Telefoninumber on puudu."
//        "with 'phone' length greater than allowed"         | { i -> i.phone = RandomStringUtils.random(300, false, true) } || //incorrect message "Sellise registrikoodiga asutus juba eksisteerib."
        "with 'phone' length less than required" | { i -> i.phone = "1234" }                                   || "Telefoninumber peab koosnema vähemalt 5 numbrist."
        "with 'phone' containing letters"        | { i -> i.phone = "abcde2334" }                              || "Telefoninumber peab koosnema vähemalt 5 numbrist."
        "without 'email'"                        | { i -> i.email = null }                                     || "Asutuse e-mail on puudu."
//        "with incorrect 'email'"                           | { i -> i.email = "abc" } || //incorrect message "E-mail peab järgima mustrit (*@*.*). E-mail peab koosnema vähemalt 5 tähemärgist. must be a well-formed email address"
//        "with incorrect 'billing email'"                   | { i -> i.billingSettings.email = "abc" } || //incorrect message "Arve väljastamise E-mail peab järgima mustrit (*@*.*). Arve väljastamise e-mail peab koosnema vähemalt 5 tähemärgist. must be a well-formed email address"
    }
}
