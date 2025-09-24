package ee.ria.tara.model

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import groovy.transform.Canonical

@Canonical
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
class Institution {
    String name

    @JsonProperty("registry_code")
    String registryCode

    InstitutionType type

    String address
    String phone
    String email

    @JsonProperty("billing_settings")
    BillingSettings billingSettings
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
