package ee.ria.tara.model

enum Issuer {
    ESTEID2018("ESTEID2018", "esteid2018"),
    ESTEID2025("ESTEID2025", "esteid2025"),
    TEST_OF_ESTEID2018("TEST of ESTEID2018", "test_esteid2018"),
    TEST_ESTEID2025("Test ESTEID2025", "test_esteid2025"),
    COMMUNITY_ESTEID2018("COMMUNITY TEST of ESTEID2018", "community_esteid2018"),
    COMMUNITY_ESTEID2025("COMMUNITY Test ESTEID2025", "community_esteid2025"),
    // Chain configured against an unreachable CRL URL.
    NEVER_AVAILABLE("Never available", "never_available"),

    final String CN
    final String path


    Issuer(String CN, String path) {
        this.CN = CN
        this.path = path
    }
}
