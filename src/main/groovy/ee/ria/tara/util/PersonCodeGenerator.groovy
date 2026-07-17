package ee.ria.tara.util

import java.time.LocalDate
import java.time.temporal.ChronoUnit

/**
 * Generates random, structurally valid Estonian personal identification codes (isikukood):
 * 11 digits G YY MM DD SSS C, for a person born between 1900 and today.
 */
class PersonCodeGenerator {

    private static final Random RANDOM = new Random()

    /** A random valid Estonian personal code for a person born after 1900 and before now. */
    static String generateEstonianPersonCode() {
        LocalDate birthDate = randomBirthDate()
        int genderDigit = (birthDate.year >= 2000 ? 5 : 3) + RANDOM.nextInt(2) // 3/4 = 1900s, 5/6 = 2000s
        int serial = RANDOM.nextInt(999) + 1
        String first10 = String.format("%d%02d%02d%02d%03d",
                genderDigit, birthDate.year % 100, birthDate.monthValue, birthDate.dayOfMonth, serial)
        return first10 + checksum(first10)
    }

    private static LocalDate randomBirthDate() {
        LocalDate start = LocalDate.of(1900, 1, 1)
        long days = ChronoUnit.DAYS.between(start, LocalDate.now())
        return start.plusDays(RANDOM.nextLong(days + 1))
    }

    // Estonian personal code control digit: weighted sum mod 11, with a second weighting as fallback.
    private static int checksum(String first10) {
        int[] weights1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 1]
        int[] weights2 = [3, 4, 5, 6, 7, 8, 9, 1, 2, 3]
        int mod = weightedSum(first10, weights1) % 11
        if (mod < 10) {
            return mod
        }
        mod = weightedSum(first10, weights2) % 11
        return mod < 10 ? mod : 0
    }

    private static int weightedSum(String digits, int[] weights) {
        int sum = 0
        weights.eachWithIndex { weight, i -> sum += Character.getNumericValue(digits.charAt(i)) * weight }
        return sum
    }
}
