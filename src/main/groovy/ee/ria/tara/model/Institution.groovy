package ee.ria.tara.model


import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import groovy.transform.Canonical
import groovy.transform.EqualsAndHashCode
import org.apache.commons.lang3.RandomStringUtils

import java.util.concurrent.CopyOnWriteArrayList

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is

@EqualsAndHashCode(excludes = ['clients', 'createdAt', 'updatedAt'])
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
class Institution {

    @JsonProperty("client_ids")
    Set<String> clientIds
    String name
    @JsonProperty("registry_code")
    String registryCode
    InstitutionType type
    String address
    String phone
    String email
    @JsonProperty("billing_settings")
    BillingSettings billingSettings

    @JsonProperty("created_at")
    String createdAt
    @JsonProperty("updated_at")
    String updatedAt

    @JsonIgnore
    List<Client> clients

    static institutionWithDefaultValues() {
        institutionWithDefaultValues("6${RandomStringUtils.random(7, false, true)}")
    }

    static Institution institutionWithDefaultValues(String registryCode) {
        new Institution(
                clientIds: new HashSet<String>(),
                clients: new CopyOnWriteArrayList<Client>(),
                name: "Test asutus ${registryCode}",
                registryCode: registryCode,
                type: new InstitutionType(type: "public"),
                address: "Testi tn 1, 12345, Testilinn",
                phone: "+3726001234",
                email: "test@example.com",
                billingSettings: new BillingSettings(email: "billing@example.com"),
        )
    }

    void sync(Institution source) {
        assertThat("Institutions should match before sync", this, is(source))
        this.with {
            createdAt = source.createdAt
            updatedAt = source.updatedAt
        }
    }
}

@Canonical
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
class InstitutionType {
    String type
}

@Canonical
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
class BillingSettings {
    String email
}
