package ee.ria.tara

import io.restassured.RestAssured
import io.restassured.filter.log.RequestLoggingFilter
import io.restassured.filter.log.ResponseLoggingFilter
import io.restassured.response.Response
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.opensaml.core.config.InitializationService
import org.opensaml.security.credential.Credential
import spock.lang.Shared
import spock.lang.Specification

import java.nio.file.Paths
import java.security.KeyStore
import java.security.Security
import java.security.cert.X509Certificate

class TaraSpecification extends Specification {
    @Shared
    Properties props = new Properties()
    static String REQUEST_TYPE_POST = "post"
    static String REQUEST_TYPE_GET = "get"
    static String REJECT_ERROR_CODE = "user_cancel"
    static String IDP_USERNAME = "xavi"
    static String IDP_PASSWORD = "creus"
    static String EIDASLOA = "E"
    static String COUNTRY = "CA"

    def setupSpec() {
        InitializationService.initialize()

        URL envFile = this.getClass().getResource('/.env')
        Properties envProperties = new Properties()
        if (envFile) {
            envFile.withInputStream {
                envProperties.load(it)
            }
            Paths.get(envProperties.getProperty("configuration_base_path"), envProperties.getProperty("configuration_path"), "application.properties").withInputStream {
                props.load(it)
            }

            //Log all requests and responses for debugging
            if (envProperties."log_all" && envProperties."log_all" != "false") {
                RestAssured.filters(new RequestLoggingFilter(), new ResponseLoggingFilter())
            }
        } else {
            this.getClass().getResource('/application.properties').withInputStream {
                props.load(it)
            }
        }
    }

    protected static Boolean isEidasPresent(Response response) {
        return response.htmlPath().getInt("**.findAll { it.'@data-tab' == 'eu-citizen' }.size()") > 0;
    }

    protected static Boolean isMidPresent(Response response) {
        return response.htmlPath().getInt("**.findAll { it.'@data-tab' == 'mobile-id' }.size()") > 0;
    }

    protected static Boolean isIdCardPresent(Response response) {
        return response.htmlPath().getInt("**.findAll { it.'@data-tab' == 'id-card' }.size()") > 0;
    }

    protected static Boolean isEidasOnlyPresent(Response response) {
        // TODO
        return false;
    }

    protected static Boolean isEmailPresent(Response response) {
        // TODO
        return false;
    }

    protected static Boolean isPhonePresent(Response response) {
        // TODO
        return false;
    }

    protected static Boolean isSmartIdPresent(Response response) {
        return response.htmlPath().getInt("**.findAll { it.'@data-tab' == 'smart-id' }.size()") > 0;
    }


}