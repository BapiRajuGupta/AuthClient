package io.mosip.authclient.auth;


import android.os.Handler;
import android.os.Looper;

import android.content.Context;
import android.widget.Toast;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import io.mosip.authclient.config.MosipConfig;
import io.mosip.authclient.config.SettingsStore;
import io.mosip.authclient.crypto.PartnerSignatureService;
import io.mosip.authclient.util.AppLogger;

public class OtpService {

    private final Context context;
    private final ObjectMapper objectMapper;
    private final AuthManagerService authManagerService;
    private final PartnerSignatureService partnerSignatureService;

    public OtpService(
            Context context,
            ObjectMapper objectMapper,
            AuthManagerService authManagerService,
            PartnerSignatureService partnerSignatureService
    ) {
        this.context =
                context.getApplicationContext();

        this.objectMapper =
                objectMapper;

        this.authManagerService =
                authManagerService;

        this.partnerSignatureService =
                partnerSignatureService;
    }

    public void requestOtp(
            String individualId,
            String individualIdType,
            OtpCallback callback
    ) {

        new Thread(() -> {

            HttpURLConnection connection = null;

            try {

                AppLogger.section(
                        "REQUESTING OTP"
                );

                SettingsStore.Settings settings =
                        new SettingsStore(
                                context,
                                objectMapper
                        ).load();

                // ----------------------------------------------------
                // 1. Build OTP request
                // ----------------------------------------------------

                ObjectNode otpRequest =
                        objectMapper.createObjectNode();

                otpRequest.put(
                        "id",
                        "mosip.identity.otp"
                );

                otpRequest.put(
                        "version",
                        "1.0"
                );

                otpRequest.put(
                        "transactionID",
                        MosipConfig.TRANSACTION_ID
                );

                otpRequest.put(
                        "requestTime",
                        java.time.Instant.now().toString()
                );

                otpRequest.put(
                        "env",
                        settings.environment
                );

                otpRequest.put(
                        "domainUri",
                        settings.domainUri
                );

                otpRequest.put(
                        "individualId",
                        individualId
                );

                otpRequest.put(
                        "individualIdType",
                        individualIdType
                );

                // Windows Auth Client behavior:
                // always request OTP through EMAIL.
                otpRequest.putArray(
                        "otpChannel"
                ).add("EMAIL");

                String otpRequestJson =
                        objectMapper.writeValueAsString(
                                otpRequest
                        );

                AppLogger.info(
                        "OTP request created"
                );

                // ----------------------------------------------------
                // 2. Get MOSIP authorization token
                // ----------------------------------------------------

                String authorizationToken =
                        authManagerService.getAuthManagerToken();

                if (authorizationToken == null
                        || authorizationToken.trim().isEmpty()) {

                    throw new Exception(
                            "Authorization token was not received"
                    );
                }

                AppLogger.info(
                        "Authorization token received"
                );

                // ----------------------------------------------------
                // 3. Sign OTP request
                // ----------------------------------------------------

                String signature =
                        partnerSignatureService.sign(
                                otpRequestJson
                        );

                if (signature == null
                        || signature.trim().isEmpty()) {

                    throw new Exception(
                            "OTP request signature was not generated"
                    );
                }

                AppLogger.info(
                        "OTP request signature generated"
                );

                // ----------------------------------------------------
                // 4. Send OTP request
                // ----------------------------------------------------

                String otpUrl =
                        settings.baseUrl
                                + "/idauthentication/v1/otp/"
                                + settings.mispLicenseKey
                                + "/"
                                + settings.partnerId
                                + "/"
                                + settings.partnerApiKey;

                URL url =
                        new URL(
                                otpUrl
                        );

                connection =
                        (HttpURLConnection)
                                url.openConnection();

                connection.setRequestMethod(
                        "POST"
                );

                connection.setConnectTimeout(
                        30000
                );

                connection.setReadTimeout(
                        30000
                );

                connection.setDoOutput(
                        true
                );

                connection.setRequestProperty(
                        "Authorization",
                        "Authorization=" + authorizationToken
                );

                connection.setRequestProperty(
                        "Cookie",
                        "Authorization=" + authorizationToken
                );

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
                        otpRequestJson.getBytes(
                                StandardCharsets.UTF_8
                        );

                try (OutputStream outputStream =
                             connection.getOutputStream()) {

                    outputStream.write(
                            requestBytes
                    );

                    outputStream.flush();
                }

                int responseCode =
                        connection.getResponseCode();

                AppLogger.info(
                        "OTP HTTP response code: "
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

                AppLogger.info(
                        "OTP response received"
                );

                AppLogger.info(
                        responseText
                );

                boolean success =
                        responseCode >= 200
                                && responseCode < 300;

                if (success) {

                    runOnUiThread(() -> {

                        Toast.makeText(
                                context,
                                "OTP sent successfully",
                                Toast.LENGTH_LONG
                        ).show();

                        if (callback != null) {
                            callback.onOtpRequested();
                        }
                    });

                } else {

                    runOnUiThread(() -> {

                        Toast.makeText(
                                context,
                                "Unable to send OTP",
                                Toast.LENGTH_LONG
                        ).show();

                        if (callback != null) {
                            callback.onOtpRequestFailed(
                                    "HTTP "
                                            + responseCode
                            );
                        }
                    });
                }

            } catch (Exception e) {

                AppLogger.error(
                        "OTP REQUEST FAILED",
                        e
                );

                runOnUiThread(() -> {

                    Toast.makeText(
                            context,
                            "OTP request failed",
                            Toast.LENGTH_LONG
                    ).show();

                    if (callback != null) {
                        callback.onOtpRequestFailed(
                                e.getMessage()
                        );
                    }
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

        java.io.ByteArrayOutputStream
                outputStream =
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

    public interface OtpCallback {

        void onOtpRequested();

        void onOtpRequestFailed(
                String message
        );
    }
}