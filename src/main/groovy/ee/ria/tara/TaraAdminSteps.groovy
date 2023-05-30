package ee.ria.tara

import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import groovy.json.JsonBuilder
import io.qameta.allure.Step
import io.restassured.response.Response

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is

// TODO: AUT-1186
class TaraAdminSteps {
    static String pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"

    @Step("Authenticate as Tara Admin")
    static void taraAdminLogin(Flow flow, String username, String password) {
        Map map = [
                "username": username,
                "password": password]
        Response loginResponse = Requests.jsonRequest(flow, flow.taraAdminService.fullBaseUrl + "/login", map)
        assertThat("Correct HTTP status code", loginResponse.statusCode, is(200))
        assertThat("No error alerts", loginResponse.jsonPath().get("error"), is(null))
        flow.taraAdminService.xsrfToken = loginResponse.getCookie("XSRF-TOKEN")
        flow.taraAdminService.jsessionId = loginResponse.getCookie("JSESSIONID")
    }

    @Step("Create institution")
    static Response createInstitution(Flow flow, String registryCode, boolean checkStatusCode = true) {
        def builder = new JsonBuilder()
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(pattern)
        LocalDateTime timestamp = LocalDateTime.now()
        timestamp = timestamp.minusDays(1L)
        def created = timestamp.format(formatter)
        timestamp = timestamp.plusMinutes(5L)
        def updated = timestamp.format(formatter)

        def root = builder {
            registry_code "${registryCode}"
            name "Albu Raamatukogu"
            //           type "public"
            type {
                type "public"
            }
            address "Albu küla, Järva vald, 73402 Järvamaa"
            phone "37213666"
            email "info@alburaamat.ee"
            billing_settings {
                email "arved@alburaamat.ee"
            }
            client_ids()
            created_at "${created}"
            updated_at "${updated}"
        }
        //  println builder.toPrettyString()

        Map cookiesMap = [
                "XSRF-TOKEN": flow.taraAdminService.xsrfToken,
                "JSESSIONID": flow.taraAdminService.jsessionId]
        Response response = Requests.postRequestAdminApiWithJsonBody(flow, flow.taraAdminService.fullBaseUrl + "/institutions", cookiesMap, builder.toString())
        if (checkStatusCode) {
            assertThat("Correct HTTP status code", response.statusCode, is(200))
        }
        return response
    }

    @Step("Who am I")
    static Response whoAmI(Flow flow, boolean checkStatusCode = true) {
        Map cookiesMap = [
                "XSRF-TOKEN": flow.taraAdminService.xsrfToken,
                "JSESSIONID": flow.taraAdminService.jsessionId]
        Response response = Requests.followRedirectWithCookie(flow, flow.taraAdminService.fullBaseUrl + "/whoami", cookiesMap)
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        return response
    }

    @Step("Delete institution")
    static Response deleteInstitution(Flow flow, String registryCode, boolean checkStatusCode = true) {
        Map cookiesMap = [
                "XSRF-TOKEN": flow.taraAdminService.xsrfToken,
                "JSESSIONID": flow.taraAdminService.jsessionId]
        Response response = Requests.deleteRequest(flow, flow.taraAdminService.fullBaseUrl + "/institutions/${registryCode}", cookiesMap)
        if (checkStatusCode) {
            assertThat("Correct HTTP status code", response.statusCode, is(200))
        }
        return response
    }

    @Step("Add client application")
    static Response addClientApplication(Flow flow, String registryCode, String clientId, boolean checkStatusCode = true) {
        def builder = new JsonBuilder()
        def root = builder {
            client_id "${clientId}"
            institution_metainfo {
                name "Albu Raamatukogu"
                registry_code "${registryCode}"
                type {
                    type "public"
                }
            }
            client_name {
                en "Registraator"
                et "Registreerija"
                ru "Регистратор"
            }
            client_short_name {
                en "Registraator (short name)"
                et "Registreerija (lühinimi)"
                ru "Регистратор (короткое имя)"
            }
            client_secret_export_settings {

            }
            redirect_uris("https://www.example.com/edasi", "https://www.example.ee/portal")
            scope(
                    "openid",
                    "idcard",
                    "mid",
                    "smartid",
                    "eidas",
                    "eidasonly",
                    "eidas:country:*",
                    "email",
                    "phone"
            )
            is_user_consent_required false
            info_notification_emails()
            sla_notification_emails()
            smartid_settings {
                should_use_additional_verification_code_check true
            }
            mid_settings {}
            client_contacts(
                    {
                        name "Uuno Udu"
                        email "uuno@tugi.ee"
                        phone "+370876543"
                        department "AIA"
                    },
                    {
                        name "Tiiu Trepp"
                        email "tiiu.trepp@tugi.ee"
                        phone "+37134567"
                        department "Kollane"
                    }
            )
        }

        // println builder.toPrettyString()

        Map cookiesMap = [
                "XSRF-TOKEN": flow.taraAdminService.xsrfToken,
                "JSESSIONID": flow.taraAdminService.jsessionId]
        Response response = Requests.postRequestAdminApiWithJsonBody(flow, flow.taraAdminService.fullBaseUrl + "/institutions/${registryCode}/clients", cookiesMap, builder.toString())
        if (checkStatusCode) {
            assertThat("Correct HTTP status code", response.statusCode, is(200))
        }
        return response
    }

    @Step("Get all clients")
    static Response getAllClients(Flow flow, String registryCode) {
        Map cookiesMap = [
                "XSRF-TOKEN": flow.taraAdminService.xsrfToken,
                "JSESSIONID": flow.taraAdminService.jsessionId]
        Requests.getRequest(flow, flow.taraAdminService.fullBaseUrl + "/institutions/${registryCode}/clients", cookiesMap)
    }

    @Step("Delete client")
    static Response deleteClient(Flow flow, String registryCode, String clientId, boolean checkStatusCode = true) {
        Map cookiesMap = [
                "XSRF-TOKEN": flow.taraAdminService.xsrfToken,
                "JSESSIONID": flow.taraAdminService.jsessionId]
        Requests.deleteRequest(flow, flow.taraAdminService.fullBaseUrl + "/institutions/${registryCode}/clients/${clientId}", cookiesMap)
    }
}
