package io.mosip.authclient.util;

import android.util.Log;

public final class AppLogger {

    private static final String TAG = "AuthClient";

    private AppLogger() {
        // Utility class
    }

    public static void d(String message) {
        Log.d(TAG, message);
    }

    public static void e(String message) {
        Log.e(TAG, message);
    }

    public static void e(String message, Throwable throwable) {
        Log.e(TAG, message, throwable);
    }

    public static void section(String title) {

        Log.d(TAG, "================================");
        Log.d(TAG, title);
        Log.d(TAG, "================================");
    }

    public static void info(String message) { Log.d(TAG, "[INFO] " + message); }
    public static void step(String message) {
        Log.d(TAG, "[STEP] " + message);
    }
    public static void success(String message) {
        Log.d(TAG, "[SUCCESS] " + message);
    }
    public static void warning(String message) {
        Log.w(TAG, "[WARNING] " + message);
    }
    public static void error(String message, Exception e) {
        Log.e(TAG, "[ERROR] " + message + " : " + e);
    }
}