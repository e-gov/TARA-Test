package ee.ria.tara.util

import ee.ria.tara.model.ErrorMessage
import io.restassured.response.Response
import io.restassured.response.ValidatableResponse
import org.apache.http.impl.EnglishReasonPhraseCatalog

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.containsInAnyOrder
import static org.hamcrest.Matchers.equalTo

class ErrorValidator {

    static void validate(Response response, ErrorMessage errorMessage) {
        validate(response, errorMessage.type, errorMessage.message)
    }

    static void validate(Response response, int statusCode, String message) {
        baseAssert(response, statusCode)
                .body("message", equalTo(message))
    }

    static void validate(Response response, int statusCode, ErrorMessage... errorMessages) {
        baseAssert(response, statusCode)

        def actualMessages = response.jsonPath().getString("message").split("; *").toList()
        def expectedMessages = errorMessages*.message

        assertThat(actualMessages, containsInAnyOrder(expectedMessages as String[]))
    }

    private static ValidatableResponse baseAssert(Response response, int statusCode) {
        response.then()
                .statusCode(statusCode)
                .contentType("application/json;charset=UTF-8")
                .body(
                        "status", equalTo(statusCode),
                        "error", equalTo(EnglishReasonPhraseCatalog.INSTANCE.getReason(statusCode, Locale.ENGLISH))
                )
    }
}
