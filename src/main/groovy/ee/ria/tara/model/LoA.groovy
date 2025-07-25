package ee.ria.tara.model

enum LoA {

    HIGH("high", "E"),
    SUBSTANTIAL("substantial", "C"),
    LOW("low", "A"),
    NOT_NOTIFIED("not notified", "http://non.eidas.eu/NotNotified/LoA/1"),

    final String label
    final String eidasTestCaLoa

    LoA(String label, String eidasTestCaLoa) {
        this.label = label
        this.eidasTestCaLoa = eidasTestCaLoa
    }

    String getEidasTestCaLoa() {
        return eidasTestCaLoa
    }

    String toString() {
        return label
    }

    static LoA fromLabel(String loa) {
        LoA result = values().find { it.label.equalsIgnoreCase(loa) }
        if (!result) throw new IllegalArgumentException("Unknown LoA label: $loa")
        return result
    }
}
