package ee.ria.tara;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.RandomStringUtils;

import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class OpenIdUtils {
    public static Boolean isTokenSignatureValid(JWKSet jwkSet, SignedJWT signedJWT) throws JOSEException {
        List<JWK> matches = new JWKSelector(new JWKMatcher.Builder()
                .keyType(KeyType.RSA)
                .build())
                .select(jwkSet);

        RSAKey rsaKey = (RSAKey) matches.get(0);
        JWSVerifier verifier = new RSASSAVerifier(rsaKey);
        return signedJWT.verify(verifier);
    }

    public static Map<String, String> getAuthorizationParameters(Flow flow) {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("ui_locales", "et");
        queryParams.put("response_type", "code");
        queryParams.put("scope", "openid");
        queryParams.put("client_id",flow.getOidcClient().getClientId());
        queryParams.put("redirect_uri", flow.getOidcClient().getFullResponseUrl().toString());
        queryParams.put("state", Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))));
        queryParams.put("nonce", Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16))));
        return queryParams;
    }
}
