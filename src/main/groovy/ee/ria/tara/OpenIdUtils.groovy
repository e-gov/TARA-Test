package ee.ria.tara

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.*
import com.nimbusds.jwt.SignedJWT
import ee.ria.tara.model.Client
import ee.ria.tara.model.LoA
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
                           client_id    : ClientStore.mockPublic.clientId,
                           redirect_uri : ClientStore.mockPublic.redirectUri,
                           state        : flow.state,
                           nonce        : flow.nonce]
        flow.setClientId(ClientStore.mockPublic.clientId)
        flow.setClientSecret(ClientStore.mockPublic.secret)
        flow.setRedirectUri(ClientStore.mockPublic.redirectUri)
        return queryParams
    }

    static Map getAuthorizationParametersWithClient(Flow flow, Client client) {
        flow.setState(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setNonce(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        Map queryParams = [ui_locales   : "et",
                           response_type: "code",
                           scope        : "openid",
                           client_id    : client.clientId,
                           redirect_uri : client.redirectUri,
                           state        : flow.state,
                           nonce        : flow.nonce]
        flow.setClientId(client.clientId)
        flow.setClientSecret(client.secret)
        flow.setRedirectUri(client.redirectUri)
        return queryParams
    }

    static Map getAuthorizationParametersForLegalPersonClient(Flow flow, String scope = "openid legalperson", String uiLocales = "et") {
        flow.setState(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setNonce(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        Map queryParams = [ui_locales   : uiLocales,
                           response_type: "code",
                           scope        : scope,
                           client_id    : ClientStore.mockLegal.clientId,
                           redirect_uri : ClientStore.mockLegal.redirectUri,
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
                           client_id    : ClientStore.specificProxyService.clientId,
                           redirect_uri : ClientStore.specificProxyService.redirectUri,
                           state        : flow.state,
                           nonce        : flow.nonce]
        return queryParams
    }

    static Map getAuthorizationParametersWithAcrValues(Flow flow, LoA acrValues) {
        getAuthorizationParametersWithAcrValues(flow, acrValues.toString())
    }

    static Map getAuthorizationParametersWithAcrValues(Flow flow, String acrValues = LoA.SUBSTANTIAL) {
        flow.setState(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        flow.setNonce(Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))))
        Map queryParams = [acr_values   : acrValues,
                           ui_locales   : "et",
                           response_type: "code",
                           scope        : "openid",
                           client_id    : ClientStore.mockPublic.clientId,
                           redirect_uri : ClientStore.mockPublic.redirectUri,
                           state        : flow.state,
                           nonce        : flow.nonce]
        return queryParams
    }
}
