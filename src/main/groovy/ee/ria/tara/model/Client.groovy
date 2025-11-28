package ee.ria.tara.model


import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonProperty.Access
import ee.ria.tara.Utils
import groovy.transform.Canonical
import groovy.transform.EqualsAndHashCode
import spock.lang.Issue

import java.time.ZonedDateTime

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is

@EqualsAndHashCode(excludes = ['id', 'createdAt', 'updatedAt', 'institution','clientSecretExportSettings'])
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
    @JsonProperty("client_secret_export_settings")
    ClientSecretExportSettings clientSecretExportSettings
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
    @JsonProperty("created_at")
    String createdAt
    @JsonProperty("updated_at")
    String updatedAt

    @JsonIgnore
    Institution institution

    static clientWithDefaultValues(Institution institution) {
        clientWithDefaultValues(institution, UUID.randomUUID().toString())
    }

    static clientWithDefaultValues(Institution institution, String clientId) {
        new Client(
                clientId: clientId,
                clientName: new ClientName(
                        en: "Test client",
                        et: "Test klient",
                        ru: "тестовый клиент",
                ),
                clientShortName: new ClientShortName(
                        en: "Tc (short name)",
                        et: "Tk (lühinimi)",
                        ru: "Тк (короткое имя)",
                ),
                institutionMetainfo: new InstitutionMetainfo(
                        name: institution.name,
                        registryCode: institution.registryCode,
                        type: institution.type,
                ),
                redirectUris: ["https://www.example.com/edasi", "https://www.example.ee/portal"],
                tokenRequestAllowedIpAddresses: ["0.0.0.0/0", "::/0"],
                tokenEndpointAuthMethod: "client_secret_basic",
                scope: ["openid", "idcard", "mid", "smartid", "eidas", "eidasonly", "eidas:country:*", "email", "phone"],

                clientContacts: [
                        new ClientContact(name: "Uuno Udu", email: "uuno@tugi.ee", phone: "+370876543", department: "AIA"),
                        new ClientContact(name: "Tiiu Trepp", email: "tiiu.trepp@tugi.ee", phone: "+37134567", department: "Kollane"),
                ],
                eidasRequesterId: "urn:uuid:" + UUID.randomUUID(),

                institution: institution
        )
    }

    String getRedirectUri() {
        redirectUris.first()
    }

    void sync(Client source, List<String> fields) {
        assertThat("Clients should match before sync", this, is(source))
        fields.each {field -> this."$field" = source."$field"}
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

@Canonical
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
class ClientSecretExportSettings {
    @JsonProperty("recipient_email")
    String recipientEmail
    @JsonProperty("recipient_id_code")
    String recipientIdCode
}
