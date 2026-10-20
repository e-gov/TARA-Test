package ee.ria.tara.testdata

interface TestPerson {

    /** OIDC subject */
    String getSubject()

    String getGivenName()

    String getFamilyName()

    /** yyyy-MM-dd */
    String getDateOfBirth()
}
