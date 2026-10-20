package ee.ria.tara.testdata

import groovy.transform.NamedParam
import groovy.transform.NamedVariant

// Smart-ID test accounts. Source: https://sk-eid.github.io/smart-id-documentation/test_accounts.html
enum SidAccount implements TestPerson {
    // SK "device link flows" OK accounts:
    OK(documentNumber: "PNOEE-40404040009-MOCK-Q",
            givenName: "OK", familyName: "TEST", dateOfBirth: "1904-04-04"),
    // Non-EE accounts
    OK_LT(documentNumber: "PNOLT-40404040009-MOCK-Q"),
    OK_LV(documentNumber: "PNOLV-040404-10003-DEMO-Q"),
    OK_BE(documentNumber: "PNOBE-04040400287-MOCK-Q"),

    // SK "notification flows" scenario accounts, also usable with the device-link mock:
    USER_REFUSED(documentNumber: "PNOEE-30403039917-MOCK-Q"),
    USER_REFUSED_DISPLAYTEXTANDPIN(documentNumber: "PNOEE-30403039928-MOCK-Q"),
    USER_REFUSED_CONFIRMATIONMESSAGE(documentNumber: "PNOEE-30403039946-MOCK-Q"),
    TIMEOUT(documentNumber: "PNOEE-30403039983-MOCK-Q"),

    // Not on SK's list
    LONG_NAME(documentNumber: "PNOEE-47106280129-MOCK-Q",
            givenName: "ALEXANDRIA EVANGELINE ANASTASIA WILHELMINA",
            familyName: "MONTGOMERY FITZGERALD VANDERBILT-HART",
            dateOfBirth: "1971-06-28"),

    final String documentNumber
    final String givenName
    final String familyName
    final String dateOfBirth

    @NamedVariant
    SidAccount(@NamedParam(required = true) String documentNumber, @NamedParam String givenName = null,
               @NamedParam String familyName = null, @NamedParam String dateOfBirth = null) {
        this.documentNumber = documentNumber
        this.givenName = givenName
        this.familyName = familyName
        this.dateOfBirth = dateOfBirth
    }

    String getCountry() {
        documentNumber.substring(3, 5)
    }

    String getIdCode() {
        documentNumber.substring(6).replaceFirst(/-[A-Z0-9]{4}-N?Q$/, "")
    }

    @Override
    String getSubject() {
        country + idCode
    }
}
