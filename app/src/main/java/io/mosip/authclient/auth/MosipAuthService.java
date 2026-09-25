package io.mosip.authclient.auth;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.authclient.config.SettingsStore;
import io.mosip.authclient.util.AppLogger;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class MosipAuthService {

    public interface AuthCallback {

        void onAuthenticationSuccess(
                String message
        );

        void onAuthenticationFailed(
                String message
        );

        void onAuthenticationError(
                String message
        );
    }

    private final Context context;
    private final SettingsStore settingsStore;
    private final ObjectMapper objectMapper;

    public MosipAuthService(Context context) {

        this.context =
                context.getApplicationContext();

        this.objectMapper =
                new ObjectMapper();

        this.settingsStore =
                new SettingsStore(
                        context,
                        objectMapper
                );
    }

    public void sendAuthRequest(
            String authRequestJson,
            String signature,
            String authorizationToken,
            AuthCallback callback
    ) {

        new Thread(() -> {

            HttpURLConnection connection = null;

            try {

                AppLogger.section(
                        "SENDING MOSIP AUTH REQUEST"
                );

                // ----------------------------------------------------
                // Load current settings
                // ----------------------------------------------------

                SettingsStore.Settings settings =
                        settingsStore.load();

                String authUrl =
                        settings.baseUrl
                                + "/idauthentication/v1/auth/"
                                + settings.mispLicenseKey
                                + "/"
                                + settings.partnerId
                                + "/"
                                + settings.partnerApiKey;

                URL url =
                        new URL(authUrl);

                connection =
                        (HttpURLConnection)
                                url.openConnection();

                connection.setRequestMethod("POST");
                connection.setConnectTimeout(30000);
                connection.setReadTimeout(30000);
                connection.setDoOutput(true);

                // ----------------------------------------------------
                // MOSIP Authorization
                // ----------------------------------------------------

                connection.setRequestProperty(
                        "Authorization",
                        "Authorization=" + authorizationToken
                );

                connection.setRequestProperty(
                        "Cookie",
                        "Authorization=" + authorizationToken
                );

                // ----------------------------------------------------
                // Detached JWS signature
                // ----------------------------------------------------

                connection.setRequestProperty(
                        "Signature",
                        signature
                );

                connection.setRequestProperty(
                        "Content-Type",
                        "application/json"
                );

                connection.setRequestProperty(
                        "Accept",
                        "application/json"
                );

                // ----------------------------------------------------
                // Send request
                // ----------------------------------------------------

                byte[] requestBytes =
                        authRequestJson.getBytes(
                                StandardCharsets.UTF_8
                        );

                try (OutputStream outputStream =
                             connection.getOutputStream()) {

                    outputStream.write(requestBytes);
                    outputStream.flush();
                }

                // ----------------------------------------------------
                // Read response
                // ----------------------------------------------------

                int responseCode =
                        connection.getResponseCode();

                AppLogger.info(
                        "Auth HTTP response code: "
                                + responseCode
                );

                InputStream stream;

                if (responseCode >= 200
                        && responseCode < 300) {

                    stream =
                            connection.getInputStream();

                } else {

                    stream =
                            connection.getErrorStream();
                }

                String responseText = "";

                if (stream != null) {

                    responseText =
                            new String(
                                    readBytes(stream),
                                    StandardCharsets.UTF_8
                            );
                }

                // Do NOT log complete authentication response.
                AppLogger.info(
                        "MOSIP auth response received"
                );

                // ----------------------------------------------------
                // Parse MOSIP authentication response
                // ----------------------------------------------------

                AuthResult authResult =
                        parseAuthResponse(
                                responseCode,
                                responseText
                        );

                // ----------------------------------------------------
                // Show result on UI
                // ----------------------------------------------------

                runOnUiThread(() -> {

                    if (authResult.success) {

                        AppLogger.success(
                                "Authentication successful"
                        );

                        if (callback != null) {
                            callback.onAuthenticationSuccess(
                                    authResult.message
                            );
                        }

                    } else {

                        AppLogger.warning(
                                "Authentication failed: "
                                        + authResult.message
                        );

                        if (callback != null) {
                            callback.onAuthenticationFailed(
                                    authResult.message
                            );
                        }
                    }
                });

            } catch (Exception e) {

                AppLogger.error(
                        "MOSIP AUTH REQUEST FAILED",
                        e
                );

                if (callback != null) {
                    runOnUiThread(() ->
                            callback.onAuthenticationError(
                                    "Authentication could not be completed. Please try again."
                            )
                    );
                }
            } finally {

                if (connection != null) {
                    connection.disconnect();
                }
            }

        }).start();
    }

    // ================================================================
    // Parse MOSIP authentication response
    // ================================================================

    private AuthResult parseAuthResponse(
            int responseCode,
            String responseText
    ) {

        // ------------------------------------------------------------
        // HTTP/network/server failure
        // ------------------------------------------------------------

        if (responseCode < 200
                || responseCode >= 300) {

            String message =
                    extractMosipErrorMessage(
                            responseText
                    );

            if (message != null
                    && !message.trim().isEmpty()) {

                return AuthResult.failure(
                        message
                );
            }

            return AuthResult.failure(
                    "Authentication request failed. "
                            + "Please try again."
            );
        }

        // ------------------------------------------------------------
        // Empty response
        // ------------------------------------------------------------

        if (responseText == null
                || responseText.trim().isEmpty()) {

            return AuthResult.failure(
                    "No response received from authentication server."
            );
        }

        try {

            JsonNode root =
                    objectMapper.readTree(
                            responseText
                    );

            // --------------------------------------------------------
            // Check response.authStatus
            // --------------------------------------------------------

            JsonNode responseNode =
                    root.get("response");

            if (responseNode != null
                    && responseNode.has("authStatus")) {

                boolean authStatus =
                        responseNode
                                .get("authStatus")
                                .asBoolean(false);

                if (authStatus) {

                    return AuthResult.success();
                }
            }

            // --------------------------------------------------------
            // Authentication failed.
            // Read MOSIP errors.
            // --------------------------------------------------------

            String message =
                    extractMosipErrorMessage(
                            root
                    );

            if (message != null
                    && !message.trim().isEmpty()) {

                return AuthResult.failure(
                        message
                );
            }

            return AuthResult.failure(
                    "Authentication failed. "
                            + "Please try again."
            );

        } catch (Exception e) {

            // Technical parsing problem.
            AppLogger.error(
                    "Unable to parse MOSIP authentication response",
                    e
            );

            return AuthResult.failure(
                    "Authentication failed. "
                            + "Please try again."
            );
        }
    }

    // ================================================================
    // Extract MOSIP error message
    // ================================================================

    private String extractMosipErrorMessage(
            String responseText
    ) {

        if (responseText == null
                || responseText.trim().isEmpty()) {

            return null;
        }

        try {

            JsonNode root =
                    objectMapper.readTree(
                            responseText
                    );

            return extractMosipErrorMessage(
                    root
            );

        } catch (Exception e) {

            AppLogger.error(
                    "Unable to parse MOSIP error response",
                    e
            );

            return null;
        }
    }

    private String extractMosipErrorMessage(
            JsonNode root
    ) {

        if (root == null) {
            return null;
        }

        JsonNode errors =
                root.get("errors");

        if (errors == null
                || !errors.isArray()
                || errors.isEmpty()) {

            return null;
        }

        JsonNode firstError =
                errors.get(0);

        if (firstError == null) {
            return null;
        }

        // ------------------------------------------------------------
        // Prefer actionMessage because it is intended for user action.
        // ------------------------------------------------------------

        String actionMessage =
                getText(
                        firstError,
                        "actionMessage"
                );

        String errorMessage =
                getText(
                        firstError,
                        "errorMessage"
                );

        String errorCode =
                getText(
                        firstError,
                        "errorCode"
                );

        if (actionMessage != null
                && !actionMessage.trim().isEmpty()) {

            return actionMessage;
        }

        if (errorMessage != null
                && !errorMessage.trim().isEmpty()) {

            return errorMessage;
        }

        if (errorCode != null
                && !errorCode.trim().isEmpty()) {

            return "Authentication failed. "
                    + "Error code: "
                    + errorCode;
        }

        return null;
    }

    private String getText(
            JsonNode node,
            String field
    ) {

        JsonNode value =
                node.get(field);

        if (value == null
                || value.isNull()) {

            return null;
        }

        String text =
                value.asText();

        if (text == null
                || text.trim().isEmpty()) {

            return null;
        }

        return text.trim();
    }

    // ================================================================
    // Read response
    // ================================================================

    private byte[] readBytes(
            InputStream inputStream
    ) throws Exception {

        byte[] buffer =
                new byte[8192];

        java.io.ByteArrayOutputStream outputStream =
                new java.io.ByteArrayOutputStream();

        int bytesRead;

        while ((bytesRead =
                inputStream.read(buffer)) != -1) {

            outputStream.write(
                    buffer,
                    0,
                    bytesRead
            );
        }

        return outputStream.toByteArray();
    }

    // ================================================================
    // Run on UI thread
    // ================================================================

    private void runOnUiThread(
            Runnable action
    ) {

        new Handler(
                Looper.getMainLooper()
        ).post(action);
    }

    // ================================================================
    // Authentication result
    // ================================================================

    private static class AuthResult {

        private final boolean success;
        private final String message;

        private AuthResult(
                boolean success,
                String message
        ) {

            this.success = success;
            this.message = message;
        }

        static AuthResult success() {

            return new AuthResult(
                    true,
                    "Authentication successful"
            );
        }

        static AuthResult failure(
                String message
        ) {

            return new AuthResult(
                    false,
                    message
            );
        }
    }
}