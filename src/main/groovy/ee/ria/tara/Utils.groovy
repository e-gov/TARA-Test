package ee.ria.tara

import io.restassured.response.Response
import org.apache.commons.lang3.StringUtils
import org.apache.http.client.utils.URLEncodedUtils
import org.json.JSONObject

import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.ZonedDateTime

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.lessThan

class Utils {

    static String getParamValueFromResponseHeader(Response response, String paramName) {
        String[] parameters = response.header("location").toURL().getQuery().split("&")
        String paramValue = null
        parameters.each {
            if (it.split("=")[0] == paramName) {
                paramValue = it.split("=")[1]
            }
        }
        if (paramValue != null) {
            return URLDecoder.decode(paramValue, "UTF-8")
        } else {
            return null
        }
    }

    static String getCertificateAsString(String filename) {
        return new File(filename).readLines().join()
    }

    static JSONObject getWebEidAuthTokenParameters(Flow flow, String signature) {
        JSONObject formParams = ["authToken": ["algorithm"            : "ES384",
                                               "appVersion"           : "https://web-eid.eu/web-eid-app/releases/2.0.2+566",
                                               "format"               : "web-eid:1.0",
                                               "signature"            : signature,
                                               "unverifiedCertificate": flow.authCertificate]]
        return formParams
    }

    static signAuthenticationValue(Flow flow, String origin, String challenge, byte[] p12Bytes, String keyStorePassword = "1234") {
        KeyStore keyStore = KeyStore.getInstance("PKCS12")
        char[] password = keyStorePassword.toCharArray()
        new ByteArrayInputStream(p12Bytes).withCloseable { is ->
            keyStore.load(is, password)
        }
        signAuthenticationValue(flow, origin, challenge, keyStore, password)
    }

    static signAuthenticationValue(Flow flow, String origin, String challenge, String keyStorePath = "src/test/resources/EE38001085718_auth_EC_TEST_of_ESTEID2018.p12", String keyStorePassword = "1234") {
        KeyStore keyStore = KeyStore.getInstance("PKCS12")
        char[] password = keyStorePassword.toCharArray()
        keyStore.load(new FileInputStream(keyStorePath), password)
        signAuthenticationValue(flow, origin, challenge, keyStore, password)
    }

    static signAuthenticationValue(Flow flow, String origin, String challenge, KeyStore keyStore, char[] password) {
        //Read keys
        String alias = keyStore.aliases().find { keyStore.isKeyEntry(it) }
        if (alias == null) {
            throw new IllegalStateException("No key entry found in keystore")
        }
        Certificate certificate = keyStore.getCertificate(alias)
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password)

        //Set authentication certificate to flow for authToken unverifiedCertificate value
        flow.setAuthCertificate(Base64.getEncoder().encodeToString(certificate.getEncoded()))

        //Hash origin & challenge nonce
        MessageDigest md = MessageDigest.getInstance("SHA-384")
        byte[] originDigest = md.digest(origin.getBytes())
        byte[] challengeDigest = md.digest(challenge.getBytes())

        //Combine origin and challenge nonce hashes to create authentication value to be signed
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream()
        outputStream.write(originDigest)
        outputStream.write(challengeDigest)

        byte[] authValue = outputStream.toByteArray()

        //Sign authentication value
        Signature ecdsaSign = Signature.getInstance("SHA384withECDSAinP1363Format")
        ecdsaSign.initSign(privateKey)
        ecdsaSign.update(authValue)
        byte[] signature = ecdsaSign.sign()
        String encodedSignature = Base64.getEncoder().encodeToString(signature)
        return encodedSignature
    }

    static String portCheck(String port) {
        if (port != null && port.isInteger()) {
            return ":${port}"
        } else {
            return ""
        }
    }

    static boolean isRunningInDocker() {
        if (StringUtils.containsIgnoreCase(System.getProperty('os.name'), 'linux')) {
            def cgroupFile = new File('/proc/1/cgroup')
            if (cgroupFile.exists() && cgroupFile.text.contains('docker')) {
                return true
            }
            def cgroupV2File = new File('/proc/1/mountinfo')
            if (cgroupV2File.exists() && cgroupV2File.text.contains('docker')) {
                return true
            }
        }
        return false
    }

    static boolean isLocal() {
        return !isRunningInDocker()
    }

    static verifyTimestampAge(ZonedDateTime timeStamp, long secondsRange) {
        long timestampAge = Duration.between(timeStamp, ZonedDateTime.now()).abs().seconds
        assertThat("Timestamp should be within " + secondsRange + "seconds", timestampAge, lessThan(secondsRange))
    }

    static Map<String, String> parseQueryParams(String url) {
        URLEncodedUtils.parse(new URI(url), StandardCharsets.UTF_8)
                .collectEntries { [(it.name): it.value] }
    }

    static X509Certificate[] getCertificateChainFromKeystore(String keyStorePath, String password) {
        KeyStore keyStore = KeyStore.getInstance("PKCS12")
        new FileInputStream(keyStorePath).withCloseable { fis ->
            keyStore.load(fis, password.toCharArray())
        }
        return getCertificateChainFromKeystore(keyStore)
    }

    static X509Certificate[] getCertificateChainFromKeystore(byte[] p12Bytes, String password) {
        KeyStore keyStore = KeyStore.getInstance("PKCS12")
        new ByteArrayInputStream(p12Bytes).withCloseable { is ->
            keyStore.load(is, password.toCharArray())
        }
        return getCertificateChainFromKeystore(keyStore)
    }

    static X509Certificate[] getCertificateChainFromKeystore(KeyStore keyStore) {
        String alias = keyStore.aliases().find { keyStore.isKeyEntry(it) }
        if (alias == null) {
            throw new IllegalStateException("No key entry found in keystore")
        }
        Certificate[] chain = keyStore.getCertificateChain(alias)
        if (chain == null || chain.length == 0) {
            throw new IllegalStateException("No certificate chain for key entry '${alias}' in keystore")
        }
        return chain.collect { it as X509Certificate } as X509Certificate[]
    }

    // Loads an X.509 certificate from a PEM file.
    static X509Certificate loadCertificate(String pemPath) {
        String content = new File(pemPath).text
        int begin = content.indexOf("-----BEGIN CERTIFICATE-----")
        int end = content.indexOf("-----END CERTIFICATE-----")
        if (begin < 0 || end < 0) {
            throw new IllegalStateException("No PEM certificate block found in: ${pemPath}")
        }
        String pem = content.substring(begin, end + "-----END CERTIFICATE-----".length())
        return CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem.getBytes("UTF-8"))) as X509Certificate
    }
}

