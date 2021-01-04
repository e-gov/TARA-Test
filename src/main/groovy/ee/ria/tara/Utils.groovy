package ee.ria.tara

import org.apache.xml.security.exceptions.Base64DecodingException
import java.net.URLEncoder
import org.spockframework.lang.Wildcard

import java.nio.charset.StandardCharsets
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import io.restassured.response.Response

class Utils {

    static Map setParameter(Map hashMap, Object param, Object paramValue) {
        if (!(param instanceof Wildcard)) {
            if (!(paramValue instanceof Wildcard)) {
                hashMap.put(param, paramValue)
            } else {
                hashMap.put(param, "")
            }
        }
        return hashMap
    }

    static boolean isValidUUID(String uuid) {
        def matcher = uuid =~ /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/
        return matcher.matches()
    }

    static boolean isValidDateTime(String datetime) {
        String pattern = "yyyy-MM-dd HH:mm:ss SSS"
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(pattern)
        LocalDateTime timestamp = LocalDateTime.parse(datetime, formatter)
        if (datetime.equals(timestamp.format(pattern)))
            return true
        else
            return false
    }

    static boolean isValidXMLDateTime(String datetime) {
        String pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(pattern)
        LocalDateTime timestamp = LocalDateTime.parse(datetime, formatter)
        if (datetime.equals(timestamp.format(pattern)))
            return true
        else
            return false
    }

    static boolean isBase64EncodedString(String encodedString) {
        if (encodedString.isBlank()) {
            return false
        } else {
            try {
                String string = new String(Base64.getDecoder().decode(encodedString), StandardCharsets.UTF_8)
            } catch (Base64DecodingException e) {
                return false
            }
            return true
        }
    }

    static String decodeBase64(String encodedString) {
        return new String(Base64.getDecoder().decode(encodedString), StandardCharsets.UTF_8)
    }

    static String getParamValueFromResponseHeader(Response response, String paramName) {
        String[] parameters = response.getHeader("location").toURL().getQuery().split("&")
        String paramValue = null
        parameters.each {
            if (it.split("=")[0] == paramName) {
                paramValue = it.split("=")[1]
            }
        }
        return paramValue
    }

    static String encodeUrl(String inputString) {
        return URLEncoder.encode(inputString, "UTF-8")
    }

    static String getCertificateAsString(String filename) {
        return new File(filename).readLines().join()
    }
}
