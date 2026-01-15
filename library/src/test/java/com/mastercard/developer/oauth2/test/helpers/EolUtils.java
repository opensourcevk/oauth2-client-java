package com.mastercard.developer.oauth2.test.helpers;

/**
 * Utility class for handling end-of-line (EOL) characters in strings.
 */
public final class EolUtils {

    private EolUtils() {
        // Utility
    }

    /**
     * Collapses any Unicode line terminator to '\n' for cross-platform comparisons.
     */
    public static String normalizeEOL(String s) {
        return s == null ? null : s.replaceAll("\\R", "\n");
    }
}
