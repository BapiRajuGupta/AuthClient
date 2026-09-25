package io.mosip.authclient.auth;

import android.content.Context;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import io.mosip.authclient.config.SettingsStore;
import io.mosip.authclient.crypto.CertificateService;
import io.mosip.authclient.util.AppLogger;

public class AuthManagerService
        implements CertificateService.MosipAuthManagerTokenProvider {

    private final ObjectMapper objectMapper;
    private final SettingsStore settingsStore;

    public AuthManagerService(
            Context context,
            ObjectMapper objectMapper
    ) {
        this.objectMapper = objectMapper;
        this.settingsStore =
                new SettingsStore(context, objectMapper);
    }

    @Override
    public String getAuthManagerToken()
            throws Exception {

        AppLogger.section(
                "GETTING AUTH MANAGER TOKEN"
        );

        // ------------------------------------------------------------
        // Load current settings
        // ------------------------------------------------------------

        SettingsStore.Settings settings =
                settingsStore.load();

        URL url =
                new URL(
                        settings.authManagerUrl
                );

        HttpURLConnection connection =
                (HttpURLConnection)
                        url.openConnection();

        connection.setRequestMethod(
                "POST"
        );

        connection.setConnectTimeout(
                10000
        );

        connection.setReadTimeout(
                10000
        );

        connection.setDoOutput(
                true
        );

        connection.setRequestProperty(
                "Content-Type",
                "application/json"
        );

        connection.setRequestProperty(
                "Accept",
                "application/json"
        );

        // ------------------------------------------------------------
        // Build Auth Manager request
        // ------------------------------------------------------------

        ObjectNode requestBody =
                objectMapper.createObjectNode();

        requestBody.put(
                "clientId",
                settings.authManagerClientId
        );

        requestBody.put(
                "secretKey",
                settings.authManagerSecret
        );

        requestBody.put(
                "appId",
                settings.authManagerAppId
        );

        ObjectNode wrapper =
                objectMapper.createObjectNode();

        wrapper.put(
                "requesttime",
                getCurrentUtcTimestamp()
        );

        wrapper.set(
                "request",
                requestBody
        );

        String requestJson =
                objectMapper.writeValueAsString(
                        wrapper
                );

        AppLogger.info(
                "Auth Manager request created"
        );

        AppLogger.info(
                "Auth Manager URL: "
                        + settings.authManagerUrl
        );

        // Do NOT log requestJson because it contains secretKey.

        // ------------------------------------------------------------
        // Send request
        // ------------------------------------------------------------

        try (OutputStream outputStream =
                     connection.getOutputStream()) {

            outputStream.write(
                    requestJson.getBytes(
                            StandardCharsets.UTF_8
                    )
            );

            outputStream.flush();
        }

        int responseCode =
                connection.getResponseCode();

        AppLogger.info(
                "Auth Manager HTTP response: "
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

        if (responseCode < 200
                || responseCode >= 300) {

            throw new Exception(
                    "Auth Manager failed: HTTP "
                            + responseCode
            );
        }

        // ------------------------------------------------------------
        // Get Authorization cookie
        // ------------------------------------------------------------

        String authorizationToken = null;

        Map<String, List<String>> headers =
                connection.getHeaderFields();

        if (headers != null) {

            for (Map.Entry<String, List<String>> entry :
                    headers.entrySet()) {

                String headerName =
                        entry.getKey();

                if (headerName == null) {
                    continue;
                }

                if ("Set-Cookie".equalsIgnoreCase(
                        headerName
                )) {

                    List<String> cookies =
                            entry.getValue();

                    if (cookies == null) {
                        continue;
                    }

                    for (String cookie : cookies) {

                        String token =
                                extractAuthorizationCookie(
                                        cookie
                                );

                        if (token != null
                                && !token.isEmpty()) {

                            authorizationToken =
                                    token;

                            break;
                        }
                    }
                }

                if (authorizationToken != null) {
                    break;
                }
            }
        }

        if (authorizationToken == null
                || authorizationToken.isEmpty()) {

            throw new Exception(
                    "Auth Manager did not return Authorization token"
            );
        }

        AppLogger.success(
                "Auth Manager token received successfully"
        );

        AppLogger.info(
                "Authorization token length: "
                        + authorizationToken.length()
        );

        connection.disconnect();

        return authorizationToken;
    }

    private String extractAuthorizationCookie(
            String cookie
    ) {

        if (cookie == null) {
            return null;
        }

        String[] parts =
                cookie.split(";");

        for (String part : parts) {

            String trimmed =
                    part.trim();

            if (trimmed.regionMatches(
                    true,
                    0,
                    "Authorization=",
                    0,
                    "Authorization=".length()
            )) {

                return trimmed.substring(
                        "Authorization=".length()
                );
            }
        }

        return null;
    }

    private byte[] readBytes(
            InputStream inputStream
    ) throws Exception {

        java.io.ByteArrayOutputStream output =
                new java.io.ByteArrayOutputStream();

        byte[] buffer =
                new byte[4096];

        int length;

        while ((length =
                inputStream.read(buffer)) != -1) {

            output.write(
                    buffer,
                    0,
                    length
            );
        }

        return output.toByteArray();
    }

    private String getCurrentUtcTimestamp() {

        return java.time.Instant
                .now()
                .toString();
    }
}