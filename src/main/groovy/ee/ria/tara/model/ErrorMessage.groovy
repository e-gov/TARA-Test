package ee.ria.tara.model

import org.apache.http.HttpStatus

enum ErrorMessage {

    // General errors
    AUTH_TITLE(HttpStatus.SC_BAD_REQUEST, "Kasutaja tuvastamine ebaõnnestus."),
    INVALID_LOGIN_CHALLENGE(HttpStatus.SC_BAD_REQUEST, "Vigane päring. Päringu volituskood ei ole korrektne."),
//    INVALID_GOVSSO_LOGIN_CHALLENGE(TBD, "Vigane päring. GovSSO päringu volituskood ei ole korrektne."),
//    NO_ALLOWED_AUTHMETHODS(TBD, "Autentimispäring ei ole korrektne. Soovitud autentimistasemele vastavaid autentimisvahendeid pole antud infosüsteemile lubatud."),
    SESSION_NOT_FOUND(HttpStatus.SC_BAD_REQUEST, "Teie seanssi ei leitud! Seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."),
    SESSION_STATE_INVALID(HttpStatus.SC_BAD_REQUEST, "Ebakorrektne päring. Vale seansi staatus."),
//    AUTH_FLOW_TIMEOUT(TBD, "Autentimiseks ettenähtud aeg lõppes. Peate autentimisprotsessi teenusepakkuja juurest uuesti alustama."),
    INVALID_REQUEST(HttpStatus.SC_BAD_REQUEST, "Ebakorrektne päring."),
    INVALID_CSRF_TOKEN(HttpStatus.SC_FORBIDDEN, "Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."),
    INTERNAL_ERROR(HttpStatus.SC_INTERNAL_SERVER_ERROR, "Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."),
    INVALID_OIDC_CLIENT(HttpStatus.SC_BAD_REQUEST, "Kliendi autentimine ebaõnnestus. Tundmatu klient."),
    INVALID_OIDC_REQUEST(HttpStatus.SC_BAD_REQUEST, "Kliendi autentimine ebaõnnestus (võimalikud põhjused: tundmatu klient, kliendi autentimist pole kaasatud, või toetamata autentimismeetod)"),
//    GENERAL(TBD, "Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."),
    MISSING_SCOPE(HttpStatus.SC_BAD_REQUEST, "Päringus puudub scope parameeter."),

    // ID-card errors
    IDC_CERT_EXPIRED(HttpStatus.SC_BAD_REQUEST, "ID-kaardi sertifikaadid ei kehti."),
    IDC_REVOKED(HttpStatus.SC_BAD_REQUEST, "ID-kaardi sertifikaadid on peatatud või tühistatud. Palun pöörduge Politsei- ja Piirivalveameti teenindusse."),

    // MID-REST errors
    MID_INTERNAL_ERROR(HttpStatus.SC_BAD_REQUEST, "Mobiil-ID teenuses esinevad tehnilised tõrked. Palun proovige mõne aja pärast uuesti."),
    MID_INVALID_IDENTITY_CODE(HttpStatus.SC_BAD_REQUEST, "Teie poolt sisestatud isikukood ei olnud korrektne. Palun pöörduge tagasi autentimismeetodite valiku juurde ja veenduge, et sisestate korrektse isikukoodi."),
    MID_INVALID_PHONE_NUMBER(HttpStatus.SC_BAD_REQUEST, "Telefoninumber ei ole korrektne."),
    MID_EXPIRED_TRANSACTION(HttpStatus.SC_BAD_REQUEST, "Kasutaja ei autentinud mobiiltelefonil oodatud aja jooksul. Palun proovige uuesti."),
    MID_USER_CANCEL(HttpStatus.SC_BAD_REQUEST, "Kasutaja katkestas mobiiltelefonil Mobiil-ID autentimise."),
    MID_PHONE_ABSENT(HttpStatus.SC_BAD_REQUEST, "Kasutaja mobiiltelefon on levialast väljas."),
    MID_SIM_ERROR(HttpStatus.SC_BAD_REQUEST, "Kasutaja mobiiltelefoni SIM-kaardiga tekkis tõrge."),
    MID_DELIVERY_ERROR(HttpStatus.SC_BAD_REQUEST, "Kasutaja mobiiltelefoni ei saa Mobiil-ID autentimise sõnumeid saata."),
    MID_NOT_MID_CLIENT(HttpStatus.SC_BAD_REQUEST, "Kasutajal pole telefoninumbril Mobiil-ID lepingut."),
    MID_SIGNATURE_HASH_MISMATCH(HttpStatus.SC_BAD_REQUEST, "Autentimine Mobiil-ID-ga ei õnnestunud. Testi oma Mobiil-ID toimimist DigiDoc4 kliendis <a target=\"_blank\" href=\"https://www.id.ee/artikkel/soovid-arvutis-digiallkirja-anda/\">siin!</a>"),

    // Smart-ID errors (HTML in messages)
    SID_INTERNAL_ERROR(HttpStatus.SC_BAD_REQUEST, "<span translate=\"no\" lang=\"en\">Smart-ID </span>teenuses esinevad tehnilised tõrked. Palun proovige mõne aja pärast uuesti."),
    SID_ACCOUNT_NOT_FOUND(HttpStatus.SC_BAD_REQUEST, "Kasutajal puudub<span translate=\"no\" lang=\"en\"> Smart-ID </span>konto."),
    SID_WRONG_VC(HttpStatus.SC_BAD_REQUEST, "Kasutaja valis<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses vale kontrollkoodi."),
    SID_INTERACTION_NOT_SUPPORTED(HttpStatus.SC_BAD_REQUEST, "<span translate=\"no\" lang=\"en\">Smart-ID </span>rakendus kasutaja nutiseadmes ei toeta nõutud kontrolle."),
    SID_USER_REFUSED_PIN(HttpStatus.SC_BAD_REQUEST, "Kasutaja katkestas<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses PIN koodi sisestamise."),
    SID_USER_REFUSED_VC(HttpStatus.SC_BAD_REQUEST, "Kasutaja katkestas<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses kontrollkoodi valiku."),
    SID_USER_REFUSED_AUTH(HttpStatus.SC_BAD_REQUEST, "Kasutaja katkestas autentimise<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses."),
    SID_USER_REFUSED_CONFIRMATION(HttpStatus.SC_BAD_REQUEST, "Kasutaja katkestas autentimise<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses kinnitusekraanil."),
    SID_USER_REFUSED_CONFIRMATION_VC(HttpStatus.SC_BAD_REQUEST, "Kasutaja katkestas autentimise<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses kontrollkoodi kinnituskraanil."),
    SID_SESSION_TIMED_OUT(HttpStatus.SC_BAD_REQUEST, "Kasutaja ei autentinud<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses oodatud aja jooksul. Palun proovige uuesti."),
    SID_DOCUMENT_UNUSABLE(HttpStatus.SC_BAD_REQUEST, "<span translate=\"no\" lang=\"en\">Smart-ID </span>kontoga autentimine ebaõnnestus. Palun kontakteeruge<span translate=\"no\" lang=\"en\"> Smart-ID </span> klienditoega."),
    SID_REQUEST_TIMED_OUT(HttpStatus.SC_BAD_REQUEST, "Autentimise päring<span translate=\"no\" lang=\"en\"> Smart-ID </span>teenusele aegus. Palun proovige mõne aja pärast uuesti."),

    // EIDAS errors
    EIDAS_AUTHENTICATION_FAILED(HttpStatus.SC_BAD_REQUEST, "eIDAS autentimine ebaõnnestus."),
    EIDAS_USER_CONSENT_NOT_GIVEN(HttpStatus.SC_BAD_REQUEST, "Te keeldusite e-teenusele vajalike andmete edastamiseks nõusoleku andmisest."),
    EIDAS_INCORRECT_LOA(HttpStatus.SC_BAD_REQUEST, "Teie poolt valitud välisriigi autentimisvahend on teenuse poolt nõutust madalama autentimistasemega. Palun valige mõni muu autentimisvahend."),
    EIDAS_INTERNAL_ERROR(HttpStatus.SC_BAD_GATEWAY, "eIDAS teenuses esinevad tehnilised tõrked. Palun proovige mõne aja pärast uuesti."),
    EIDAS_GENERAL_ERROR(HttpStatus.SC_BAD_REQUEST, "Autentimine ebaõnnestus sisemise vea tõttu. Palun proovige mõne aja pärast uuesti."),
    EIDAS_NOT_ALLOWED_COUNTRY(HttpStatus.SC_BAD_REQUEST, "Antud riigikood ei ole lubatud. Lubatud riigikoodid on:<span translate=\"no\"> {0}</span>"), // TODO: "Antud riigikood ei ole lubatud. Lubatud riigikoodid on:<span translate=\"no\"> {0}</span>"

    // Additional errors
    DUPLICATE_PARAMETERS(HttpStatus.SC_BAD_REQUEST, "Multiple request parameters with the same name not allowed"),

    final int type
    final String message


    ErrorMessage(int errorType, String message) {
        this.type = errorType
        this.message = message
    }

    String getMessage(Object... args) {
        if (args.length == 0) {
            return message
        } else {
            return message.replaceAll(/\{(\d+)\}/) { match, index -> args[index as int] }
        }
    }

    String toString() {
        return message
    }
}
