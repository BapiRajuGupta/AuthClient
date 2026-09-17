package io.mosip.authclient.auth;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.widget.Toast;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.authclient.config.SettingsStore;
import io.mosip.authclient.util.AppLogger;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class MosipAuthService {

    private final Context context;
    private final SettingsStore settingsStore;

    public MosipAuthService(Context context) {

        this.context =
                context.getApplicationContext();

        this.settingsStore =
                new SettingsStore(
                        context,
                        new ObjectMapper()
                );
    }

    public void sendAuthRequest(
            String authRequestJson,
            String signature,
            String authorizationToken
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

                byte[] requestBytes =
                        authRequestJson.getBytes(
                                StandardCharsets.UTF_8
                        );

                try (OutputStream outputStream =
                             connection.getOutputStream()) {

                    outputStream.write(requestBytes);
                    outputStream.flush();
                }

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

                // Do not log the complete MOSIP response.
                // It may contain sensitive authentication information.
                AppLogger.info(
                        "MOSIP auth response received"
                );

                AppLogger.info(
                        responseText
                );

                boolean success =
                        responseCode >= 200
                                && responseCode < 300;

                runOnUiThread(() -> {

                    if (success) {

                        Toast.makeText(
                                context,
                                "Auth request completed",
                                Toast.LENGTH_LONG
                        ).show();

                    } else {

                        Toast.makeText(
                                context,
                                "Auth failed: "
                                        + responseCode,
                                Toast.LENGTH_LONG
                        ).show();
                    }
                });

            } catch (Exception e) {

                AppLogger.error(
                        "MOSIP AUTH REQUEST FAILED",
                        e
                );

                runOnUiThread(() -> {

                    Toast.makeText(
                            context,
                            "Auth request failed: "
                                    + e.getMessage(),
                            Toast.LENGTH_LONG
                    ).show();
                });

            } finally {

                if (connection != null) {
                    connection.disconnect();
                }
            }

        }).start();
    }

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

    private void runOnUiThread(
            Runnable action
    ) {

        new Handler(
                Looper.getMainLooper()
        ).post(action);
    }
}