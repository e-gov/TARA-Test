package ee.ria.tara.testdata

import groovy.transform.NamedParam
import groovy.transform.NamedVariant

// Mobile-ID test accounts. Source: https://github.com/SK-EID/MID/wiki/Test-number-for-automated-testing-in-DEMO
enum MidAccount implements TestPerson {
    // Successful authentication:
    OK(idCode: "60001017716", phoneNumber: "59100366",
            givenName: "MARY ÄNN", familyName: "O'CONNEŽ-ŠUSLIK TESTNUMBER", dateOfBirth: "2000-01-01"),
    // Represents legal persons in the business register
    LEGAL_PERSON_REPRESENTATIVE(idCode: "60001017705", phoneNumber: "59000366",
            givenName: "MARY ÄNN", familyName: "O'CONNEŽ-ŠUSLIK TESTNUMBER", dateOfBirth: "2000-01-01"),
    // "TEST of ESTEID-SK 2015" certificate; typographic apostrophe in family name
    ESTEID_SK_2015(idCode: "60001018800", phoneNumber: "00000566",
            givenName: "MARY ÄNN", familyName: "O’CONNEŽ-ŠUSLIK TESTNUMBER", dateOfBirth: "2000-01-01"),
    // "TEST of EID-SK 2016" certificate
    EID_SK_2016(idCode: "60001017869", phoneNumber: "68000769",
            givenName: "EID2016", familyName: "TESTNUMBER", dateOfBirth: "2000-01-01"),
    // "TEST of SK ID Solutions EID-Q 2021E" certificate
    EID_Q_2021E(idCode: "51307149560", phoneNumber: "69930366",
            givenName: "MARY ÄNN", familyName: "O'CONNEŽ-ŠUSLIK TESTNUMBER", dateOfBirth: "2013-07-14"),

    // Error scenarios:
    NOT_MID_CLIENT(idCode: "60001019939", phoneNumber: "00000266"),
    DELIVERY_ERROR(idCode: "60001019947", phoneNumber: "07110066"),
    USER_CANCELLED(idCode: "60001019950", phoneNumber: "01100266"),
    SIGNATURE_HASH_MISMATCH(idCode: "60001019961", phoneNumber: "00000666"),
    SIM_ERROR(idCode: "60001019972", phoneNumber: "01200266"),
    PHONE_ABSENT(idCode: "60001019983", phoneNumber: "13100266"),
    TIMEOUT(idCode: "50001018908", phoneNumber: "66000266"),

    final String idCode
    final String phoneNumber
    final String givenName
    final String familyName
    final String dateOfBirth

    @NamedVariant
    MidAccount(@NamedParam(required = true) String idCode, @NamedParam(required = true) String phoneNumber,
               @NamedParam String givenName = null, @NamedParam String familyName = null,
               @NamedParam String dateOfBirth = null) {
        this.idCode = idCode
        this.phoneNumber = phoneNumber
        this.givenName = givenName
        this.familyName = familyName
        this.dateOfBirth = dateOfBirth
    }

    @Override
    String getSubject() {
        "EE" + idCode
    }
}
