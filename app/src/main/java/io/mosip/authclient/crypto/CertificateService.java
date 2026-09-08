package io.mosip.authclient.crypto;

import android.content.Context;
import android.util.Base64;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.authclient.config.MosipConfig;
import io.mosip.authclient.util.AppLogger;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CertificateService {

    private final Context context;
    private final ObjectMapper objectMapper;
    private final MosipAuthManagerTokenProvider tokenProvider;

    public CertificateService(
            Context context,
            ObjectMapper objectMapper,
            MosipAuthManagerTokenProvider tokenProvider
    ) {
        this.context = context;
        this.objectMapper = objectMapper;
        this.tokenProvider = tokenProvider;
    }

    public X509Certificate getMosipCertificate()
            throws Exception {

        AppLogger.section(
                "GETTING MOSIP CERTIFICATE"
        );

        String authorizationToken =
                tokenProvider.getAuthManagerToken();

        URL url =
                new URL(
                        MosipConfig.CERTIFICATE_URL
                );

        HttpURLConnection connection =
                (HttpURLConnection)
                        url.openConnection();

        try {

            connection.setRequestMethod("GET");

            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);

            connection.setRequestProperty(
                    "Accept",
                    "application/json"
            );

            connection.setRequestProperty(
                    "Cookie",
                    "Authorization="
                            + authorizationToken
            );

            connection.setRequestProperty(
                    "Authorization",
                    "Authorization="
                            + authorizationToken
            );

            AppLogger.step(
                    "Calling MOSIP certificate API"
            );

            int responseCode =
                    connection.getResponseCode();

            AppLogger.d(
                    "Certificate HTTP response: "
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
                        "Certificate API failed: HTTP "
                                + responseCode
                );
            }

            JsonNode root =
                    objectMapper.readTree(
                            responseText
                    );

            String certificateString =
                    root.path("response")
                            .path("certificate")
                            .asText(null);

            if (certificateString == null
                    || certificateString.isEmpty()) {

                throw new Exception(
                        "Certificate not found in MOSIP response"
                );
            }

            certificateString =
                    trimCertificate(
                            certificateString
                    );

            byte[] certificateBytes =
                    Base64.decode(
                            certificateString,
                            Base64.DEFAULT
                    );

            CertificateFactory factory =
                    CertificateFactory.getInstance(
                            "X.509"
                    );

            X509Certificate certificate =
                    (X509Certificate)
                            factory.generateCertificate(
                                    new ByteArrayInputStream(
                                            certificateBytes
                                    )
                            );

            AppLogger.success(
                    "MOSIP encryption certificate loaded"
            );

            AppLogger.d(
                    "Certificate subject: "
                            + certificate
                            .getSubjectX500Principal()
            );

            return certificate;

        } finally {

            connection.disconnect();
        }
    }

    private String trimCertificate(
            String certificate) {

        return certificate
                .replace(
                        "-----BEGIN CERTIFICATE-----",
                        ""
                )
                .replace(
                        "-----END CERTIFICATE-----",
                        ""
                )
                .replaceAll(
                        "\\s",
                        ""
                );
    }

    private byte[] readBytes(
            InputStream inputStream
    ) throws Exception {

        java.io.ByteArrayOutputStream buffer =
                new java.io.ByteArrayOutputStream();

        byte[] data =
                new byte[4096];

        int bytesRead;

        while (
                (bytesRead =
                        inputStream.read(data))
                        != -1
        ) {

            buffer.write(
                    data,
                    0,
                    bytesRead
            );
        }

        inputStream.close();

        return buffer.toByteArray();
    }

    public interface MosipAuthManagerTokenProvider {

        String getAuthManagerToken()
                throws Exception;
    }
}