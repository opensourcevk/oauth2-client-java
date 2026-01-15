package com.mastercard.developer.oauth2.test.helpers;

/**
 * Utility for reading, setting and restoring JVM system properties in tests.
 */
public final class SystemPropertyUtils {

    private SystemPropertyUtils() {
        // Utility
    }

    public static String get(String key) {
        return System.getProperty(key);
    }

    public static void set(String key, String value) {
        if (value == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, value);
        }
    }

    public static void restore(String key, String value) {
        set(key, value);
    }
}
