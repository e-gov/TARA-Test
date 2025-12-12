package ee.ria.tara.model

enum SidAccount {

    /**
     * Some description 111
     */
    EE40404049996(
            personCode: "40404049996",
            issuerCommonName: "TEST of EID-SK 2016"
    ),

    /**
     * Some description 222
     */
    EE40504040001(
            personCode: "40504040001",
            issuerCommonName: "TEST of SK ID Solutions EID-Q 2024E"
    ),


    final String personCode
    final String givenName
    final String surname
    final String commonName
    final String authCert
    final String signCert
    final String dateOfBirth
    final String issuerCommonName

    SidAccount(Map m) {
        this.personCode = (String) m.personCode
        this.givenName = (String) m.givenName
        this.surname = (String) m.surname
        this.commonName = (String) m.commonName
        this.authCert = (String) m.authCert
        this.signCert = (String) m.signCert
        this.dateOfBirth = (String) m.dateOfBirth
        this.issuerCommonName = (String) m.issuerCommonName
    }
}
