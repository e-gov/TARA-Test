package ee.ria.tara.model

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonProperty.Access
import groovy.transform.Canonical
import groovy.transform.EqualsAndHashCode

@EqualsAndHashCode(excludes = ['id'])
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
class Client {

    String id

    @JsonProperty("client_id")
    String clientId

    @JsonProperty("client_name")
    ClientName clientName

    @JsonProperty("client_short_name")
    ClientShortName clientShortName

    @JsonProperty("institution_metainfo")
    InstitutionMetainfo institutionMetainfo

    @JsonProperty("redirect_uris")
    Set<String> redirectUris

    @JsonProperty("token_request_allowed_ip_addresses")
    Set<String> tokenRequestAllowedIpAddresses

    @JsonProperty("token_endpoint_auth_method")
    String tokenEndpointAuthMethod

    Set<String> scope
    @JsonProperty(value = "_systemTest_secret", access = Access.WRITE_ONLY)
    String secret
    String description

    @JsonProperty("client_contacts")
    Set<ClientContact> clientContacts

    @JsonProperty("eidas_requester_id")
    String eidasRequesterId

    String getRedirectUri() {
        redirectUris.first()
    }
}

@Canonical
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
class ClientName {
    String et
    String en
    String ru
}

@Canonical
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
class ClientShortName {
    String et
    String en
    String ru
}

@Canonical
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
class InstitutionMetainfo {
    String name

    @JsonProperty("registry_code")
    String registryCode
    InstitutionType type
}

@Canonical
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
class ClientContact {
    String name
    String email
    String phone
    String department
}
