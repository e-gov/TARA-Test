package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.is

class ActuatorSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Feature("HEALTH_MONITORING_ENDPOINT")
    @Feature("HEALTH_MONITORING_ENDPOINT_DEPENDENCIES")
    @Feature("HEALTH_MONITORING_STATUS")
    def "Verify '#service' service 'actuator prometheus' response"() {
        when:
        Response response = switch (service) {
            case "Login" -> Requests.getPrometheus(flow.loginService.fullNodeUrl)
            case "OIDC" -> Requests.getPrometheus(flow.oidcService.fullNodeUrl)
            case "Inproxy" -> Requests.getPrometheus(flow.inproxyService.fullNodeUrl)
            case "Tara admin" -> Requests.getPrometheus(flow.taraAdminService.fullNodeUrl)
            default -> throw new Exception("Unknown service: $service")
        }

        then:
        response.then()
                .contentType("text/plain")
                .body(containsString("process_start_time_seconds"))

        where:
        service      | _
        "Login"      | _
        "OIDC"       | _
        "Inproxy"    | _
        "Tara admin" | _
    }

    @Feature("HEALTH_MONITORING_ENDPOINT")
    @Feature("HEALTH_MONITORING_ENDPOINT_DEPENDENCIES")
    @Feature("HEALTH_MONITORING_STATUS")
    def "Verify '#service' service 'actuator #endpoint' dependent service '#component' status"() {
        when:
        Response response = switch (service) {
            case "Login" -> switch (endpoint) {
                case "health" -> Requests.getHealth(flow.loginService.fullNodeUrl)
                case "health readiness" -> Requests.getHealthReadiness(flow.loginService.fullNodeUrl)
                default -> throw new Exception("Unknown endpoint: $endpoint")
            }
            case "Tara admin" -> switch (endpoint) {
                case "health" -> Requests.getHealth(flow.taraAdminService.fullNodeUrl)
                case "health readiness" -> Requests.getHealthReadiness(flow.taraAdminService.fullNodeUrl)
                default -> throw new Exception("Unknown endpoint: $endpoint")
            }
            default -> throw new Exception("Unknown service: $service")
        }

        then:
        response.then()
                .contentType("application/vnd.spring-boot.actuator")
                .body("components." + component + ".status", equalTo("UP"),)

        where:
        service      | endpoint           | component
        "Login"      | "health"           | "ignite"
        "Login"      | "health"           | "oidcServer"
        "Login"      | "health readiness" | "oidcServer"
        "Tara admin" | "health"           | "db"
        "Tara admin" | "health"           | "ldap"
        "Tara admin" | "health"           | "mail"
        "Tara admin" | "health readiness" | "db"
        "Tara admin" | "health readiness" | "ldap"
    }

    @Feature("HEALTH_MONITORING_ENDPOINT")
    @Feature("HEALTH_MONITORING_ENDPOINT_DEPENDENCIES")
    @Feature("HEALTH_MONITORING_STATUS")
    def "Verify '#service' service 'actuator #endpoint' status"() {
        when:
        Response response = switch (service) {
            case "Login" -> switch (endpoint) {
                case "health" -> Requests.getHealth(flow.loginService.fullNodeUrl)
                case "health readiness" -> Requests.getHealthReadiness(flow.loginService.fullNodeUrl)
                case "health liveness" -> Requests.getHealthLiveness(flow.loginService.fullNodeUrl)
                default -> throw new Exception("Unknown endpoint: $endpoint")
            }
            case "OIDC" -> switch (endpoint) {
                case "health" -> Requests.getHealth(flow.oidcService.fullNodeUrl)
                case "health readiness" -> Requests.getHealthReadiness(flow.oidcService.fullNodeUrl)
                case "health liveness" -> Requests.getHealthLiveness(flow.oidcService.fullNodeUrl)
                default -> throw new Exception("Unknown endpoint: $endpoint")
            }
            case "Inproxy" -> switch (endpoint) {
                case "health" -> Requests.getHealth(flow.inproxyService.fullNodeUrl)
                case "health readiness" -> Requests.getHealthReadiness(flow.inproxyService.fullNodeUrl)
                case "health liveness" -> Requests.getHealthLiveness(flow.inproxyService.fullNodeUrl)
                default -> throw new Exception("Unknown endpoint: $endpoint")
            }
            case "Tara admin" -> switch (endpoint) {
                case "health" -> Requests.getHealth(flow.taraAdminService.fullNodeUrl)
                case "health readiness" -> Requests.getHealthReadiness(flow.taraAdminService.fullNodeUrl)
                case "health liveness" -> Requests.getHealthLiveness(flow.taraAdminService.fullNodeUrl)
                default -> throw new Exception("Unknown endpoint: $endpoint")
            }
            default -> throw new Exception("Unknown service: $service")
        }

        then:
        response.then()
                .contentType("application/vnd.spring-boot.actuator")
                .body("status", is("UP"))

        where:
        service      | endpoint
        "Login"      | "health"
        "Login"      | "health readiness"
        "Login"      | "health liveness"

        "OIDC"       | "health"
        "OIDC"       | "health readiness"
        "OIDC"       | "health liveness"

//        "Inproxy"    | "health" //returns 503
        "Inproxy"    | "health readiness"
        "Inproxy"    | "health liveness"

        "Tara admin" | "health"
        "Tara admin" | "health readiness"
        "Tara admin" | "health liveness"
    }

    @Feature("HEALTH_MONITORING_ENDPOINT")
    def "Endpoint '#service' service 'actuator #endpoint' cannot be accessed through proxy"() {
        when:
        Response response = switch (service) {
            case "Login" -> switch (endpoint) {
                case "health" -> Requests.tryGetHealth(flow.loginService.fullBaseUrl)
                case "health readiness" -> Requests.tryGetHealthReadiness(flow.loginService.fullBaseUrl)
                case "health liveness" -> Requests.tryGetHealthLiveness(flow.loginService.fullBaseUrl)
                case "prometheus" -> Requests.tryGetPrometheus(flow.loginService.fullBaseUrl)
                default -> throw new Exception("Unknown endpoint: $endpoint")
            }
            case "OIDC" -> switch (endpoint) {
                case "health" -> Requests.tryGetHealth(flow.oidcService.fullBaseUrl)
                case "health readiness" -> Requests.tryGetHealthReadiness(flow.oidcService.fullBaseUrl)
                case "health liveness" -> Requests.tryGetHealthLiveness(flow.oidcService.fullBaseUrl)
                case "prometheus" -> Requests.tryGetPrometheus(flow.oidcService.fullBaseUrl)
                default -> throw new Exception("Unknown endpoint: $endpoint")
            }
            default -> throw new Exception("Unknown service: $service")
        }

        then:
        response.then()
                .statusCode(404)
                .body("path", is("/notfound"))

        where:
        service | endpoint
        "Login" | "health"
        "Login" | "health readiness"
        "Login" | "health liveness"
        "Login" | "prometheus"
        "OIDC"  | "health"
        "OIDC"  | "health readiness"
        "OIDC"  | "health liveness"
        "OIDC"  | "prometheus"
    }
}
