package ee.ria.tara

import io.restassured.response.Response
import org.json.JSONObject
import org.spockframework.lang.Wildcard

import java.security.*;
import java.security.cert.Certificate


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

    static String getParamValueFromResponseHeader(Response response, String paramName) {
        String[] parameters = response.getHeader("location").toURL().getQuery().split("&")
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

    static String encodeUrl(String inputString) {
        return URLEncoder.encode(inputString, "UTF-8")
    }

    static String getCertificateAsString(String filename) {
        return new File(filename).readLines().join()
    }

    static JSONObject getWebEidAuthTokenParameters(Flow flow, String signature) {
        JSONObject formParams = new JSONObject()
        JSONObject authToken = new JSONObject()
        formParams.put("authToken", authToken)
        authToken.put("algorithm", "ES384")
        authToken.put("appVersion", "https://web-eid.eu/web-eid-app/releases/2.0.2+566")
        authToken.put("format", "web-eid:1.0")
        authToken.put("signature", signature)
        authToken.put("unverifiedCertificate", flow.authCertificate)
        return formParams
    }

    static signAuthenticationValue(Flow flow, String origin, String challenge, String keyStore = "src/test/resources/joeorg_auth_EC.p12", String keyStorePassword = "1234") {
        //Read keystore and keys
        KeyStore store = KeyStore.getInstance("PKCS12");
        char[] password = keyStorePassword.toCharArray()
        store.load(new FileInputStream(keyStore), password)
        Certificate certificate = store.getCertificate("1")
        PrivateKey privateKey = (PrivateKey) store.getKey("1", password)

        //Set authentication certificate to flow for authToken unverifiedCertificate value
        flow.setAuthCertificate(Base64.getEncoder().encodeToString(certificate.getEncoded()))

        //Hash origin & challenge nonce
        MessageDigest md = MessageDigest.getInstance("SHA-384")
        byte[] originDigest = md.digest(origin.getBytes())
        byte[] challengeDigest = md.digest(challenge.getBytes())

        //Combine origin and challenge nonce hashes to create authentication value to be signed
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream()
        outputStream.write(originDigest);
        outputStream.write(challengeDigest);

        byte[] authValue = outputStream.toByteArray()

        //Sign authentication value
        Signature ecdsaSign = Signature.getInstance("SHA384withECDSAinP1363Format")
        ecdsaSign.initSign(privateKey)
        ecdsaSign.update(authValue)
        byte[] signature = ecdsaSign.sign()
        String encodedSignature = Base64.getEncoder().encodeToString(signature)
        return encodedSignature
    }
}

