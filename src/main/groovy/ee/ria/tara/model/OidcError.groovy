package ee.ria.tara.model

// List of OIDC supported errors with some custom TARA additions.
enum OidcError {

    // If a user cancels authentication in TARA
    USER_CANCEL("user_cancel"),
    USER_CANCEL_CONSENT("user_cancel"),

    // OpenID Connect standard errors
    INVALID_CLIENT("invalid_client"),
    INVALID_GRANT("invalid_grant"),
    INVALID_REQUEST("invalid_request"),
    INVALID_SCOPE("invalid_scope"),
    UNAUTHORIZED_CLIENT("unauthorized_client"),
    UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type"),

    INVALID_STATE("invalid_state"),
    REQUEST_UNAUTHORIZED("request_unauthorized"),
    SERVICE_ERROR("service_error"),

    final String code

    OidcError(String code) {
        this.code = code
    }

    String toString() {
        return code
    }
}
