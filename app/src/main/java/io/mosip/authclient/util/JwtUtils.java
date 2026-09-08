package io.mosip.authclient.util;

import android.util.Base64;

import java.nio.charset.StandardCharsets;

public final class JwtUtils {

    private JwtUtils() {
        // Utility class
    }

    public static byte[] getPayload(String jwt) {

        try {

            String[] parts = jwt.split("\\.");

            if (parts.length < 2) {
                throw new IllegalArgumentException(
                        "Invalid JWT"
                );
            }

            return Base64.decode(
                    parts[1],
                    Base64.URL_SAFE
                            | Base64.NO_WRAP
                            | Base64.NO_PADDING
            );

        } catch (Exception e) {

            AppLogger.e(
                    "Unable to decode JWT payload",
                    e
            );

            return null;
        }
    }

    public static String getPayloadAsString(String jwt) {

        byte[] payload = getPayload(jwt);

        if (payload == null) {
            return null;
        }

        return new String(
                payload,
                StandardCharsets.UTF_8
        );
    }
}