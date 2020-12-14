package ee.ria.tara;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import io.qameta.allure.Allure;

import java.io.IOException;
import java.text.ParseException;

public class TokenUtils {

    // From old project
    public static SignedJWT verifyTokenAndReturnSignedJwtObject(String token) throws ParseException, JOSEException, IOException {
        SignedJWT signedJWT = SignedJWT.parse(token);
        //TODO: single attachment
        addJsonAttachment("Header", signedJWT.getHeader().toString());
        addJsonAttachment("Payload", signedJWT.getJWTClaimsSet().toString());
        try {
            Allure.link("View Token in jwt.io", new io.qameta.allure.model.Link().toString(),
                    "https://jwt.io/#debugger-io?token=" + token);
        } catch (Exception e) {
            //NullPointerException when running test from IntelliJ
        }

        return signedJWT;
    }

    static void addJsonAttachment(String name, String json) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        Object jsonObject = mapper.readValue(json, Object.class);
        String prettyJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObject);
        Allure.addAttachment(name, "application/json", prettyJson, "json");
    }
}
