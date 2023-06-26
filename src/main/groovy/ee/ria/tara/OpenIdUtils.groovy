package ee.ria.tara

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.*
import com.nimbusds.jwt.SignedJWT
import org.apache.commons.codec.digest.DigestUtils
import org.apache.commons.lang3.RandomStringUtils

class OpenIdUtils {
    static Boolean isTokenSignatureValid(JWKSet jwkSet, SignedJWT signedJWT) throws JOSEException {
        List<JWK> matches = new JWKSelector(new JWKMatcher.Builder()
                .keyType(KeyType.RSA)
                .build())
                .select(jwkSet)

        RSAKey rsaKey = (RSAKey) matches.get(0)
        JWSVerifier verifier = new RSASSAVerifier(rsaKey)
        return signedJWT.verify(verifier)
    }

    static Map getAuthorizationParameters(Flow flow, String scope = "openid", String uiLocales = "et") {
        flow.setState(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setNonce(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        Map queryParams = [ui_locales   : uiLocales,
                           response_type: "code",
                           scope        : scope,
                           client_id    : flow.oidcClientPublic.clientId,
                           redirect_uri : flow.oidcClientPublic.fullResponseUrl.toString(),
                           state        : flow.state,
                           nonce        : flow.nonce]
        return queryParams
    }

    static Map getAuthorizationParametersWithClient(Flow flow, String scope = "openid", String clientId, String redirectUri) {
        flow.setState(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setNonce(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        Map queryParams = [ui_locales   : "et",
                           response_type: "code",
                           scope        : scope,
                           client_id    : clientId,
                           redirec_uri  : redirectUri,
                           state        : flow.state,
                           nonce        : flow.nonce]
        return queryParams
    }

    static Map getAuthorizationParametersForLegalPersonClient(Flow flow, String scope = "openid legalperson", String uiLocales = "et") {
        flow.setState(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setNonce(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        Map queryParams = [ui_locales   : uiLocales,
                           response_type: "code",
                           scope        : scope,
                           client_id    : flow.oidcClientLegal.clientId,
                           redirec_uri  : flow.oidcClientLegal.fullResponseUrl.toString(),
                           state        : flow.state,
                           nonce        : flow.nonce]
        return queryParams
    }

    static Map getAuthorizationParametersForSpecificProxyService(Flow flow, String scope = "openid", String uiLocales = "et") {
        flow.setState(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setNonce(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        Map queryParams = [ui_locales   : uiLocales,
                           response_type: "code",
                           scope        : scope,
                           client_id    : flow.specificProxyService.clientId,
                           redirect_uri : flow.specificProxyService.fullResponseUrl.toString(),
                           state        : flow.state,
                           nonce        : flow.nonce]
        return queryParams
    }

    static Map getAuthorizationParametersWithAcrValues(Flow flow, String acr_values = "substantial") {
        flow.setState(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setNonce(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        Map queryParams = [acr_values   : acr_values,
                           ui_locales   : "et",
                           response_type: "code",
                           scope        : "openid",
                           client_id    : flow.oidcClientPublic.clientId,
                           redirect_uri : flow.oidcClientPublic.fullResponseUrl.toString(),
                           state        : flow.state,
                           nonce        : flow.nonce]
        return queryParams
    }
}
