package io.mosip.authclient.auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.mosip.authclient.config.MosipConfig;
import io.mosip.authclient.crypto.MosipCryptoService;
import io.mosip.authclient.util.AppLogger;

public class AuthRequestBuilder {

    private final ObjectMapper objectMapper;

    public AuthRequestBuilder(
            ObjectMapper objectMapper
    ) {
        this.objectMapper = objectMapper;
    }

    // ============================================================
    // IDENTITY REQUEST
    // ============================================================

    /*
     * Existing method.
     *
     * Keeps current biometric authentication behavior unchanged.
     */
    public String buildIdentityRequest(
            String combinedBiometrics
    ) throws JsonProcessingException {

        return buildIdentityRequest(
                combinedBiometrics,
                null
        );
    }

    /*
     * New method.
     *
     * Supports:
     *  - Biometric only
     *  - OTP only
     *  - Biometric + OTP
     */
    public String buildIdentityRequest(
            String combinedBiometrics,
            String otp
    ) throws JsonProcessingException {

        boolean hasBiometrics =
                combinedBiometrics != null
                        && !combinedBiometrics.trim().isEmpty();

        boolean hasOtp =
                otp != null
                        && !otp.trim().isEmpty();

        if (!hasBiometrics && !hasOtp) {
            throw new IllegalArgumentException(
                    "Biometric data or OTP is required"
            );
        }

        ObjectNode identity =
                objectMapper.createObjectNode();

        // ------------------------------------------------------------
        // OTP
        // ------------------------------------------------------------

        if (hasOtp) {
            identity.put(
                    "otp",
                    otp
            );
        } else {
            identity.putNull(
                    "otp"
            );
        }

        // ------------------------------------------------------------
        // Timestamp
        // ------------------------------------------------------------

        identity.put(
                "timestamp",
                getCurrentUtcTimestamp()
        );

        // ------------------------------------------------------------
        // Demographics
        // ------------------------------------------------------------

        identity.putNull(
                "demographics"
        );

        // ------------------------------------------------------------
        // Biometrics
        // ------------------------------------------------------------

        if (hasBiometrics) {

            JsonNode biometricRoot =
                    objectMapper.readTree(
                            combinedBiometrics
                    );

            JsonNode biometrics =
                    biometricRoot.get(
                            "biometrics"
                    );

            if (biometrics == null
                    || biometrics.isNull()) {

                throw new IllegalArgumentException(
                        "Biometric data not found"
                );
            }

            identity.set(
                    "biometrics",
                    biometrics
            );

            AppLogger.d(
                    "DEBUG: Identity biometric count = "
                            + biometrics.size()
            );

        } else {

            identity.putNull(
                    "biometrics"
            );
        }

        AppLogger.d(
                "DEBUG: Identity has otp = "
                        + identity.has("otp")
        );

        AppLogger.d(
                "DEBUG: Identity has timestamp = "
                        + identity.has("timestamp")
        );

        AppLogger.d(
                "DEBUG: Identity has demographics = "
                        + identity.has("demographics")
        );

        AppLogger.d(
                "DEBUG: Identity has biometrics = "
                        + identity.has("biometrics")
        );

        return objectMapper
                .writerWithDefaultPrettyPrinter()
                .writeValueAsString(
                        identity
                );
    }

    // ============================================================
    // AUTH REQUEST
    // ============================================================

    /*
     * Existing method.
     *
     * Keeps current biometric authentication behavior unchanged:
     *
     * bio = true
     * otp = false
     */
    public String buildAuthRequest(
            MosipCryptoService.EncryptionResult encryptionResult,
            String transactionId
    ) throws JsonProcessingException {

        return buildAuthRequest(
                encryptionResult,
                transactionId,
                true,
                false
        );
    }

    /*
     * New method.
     *
     * Supports:
     *  - Biometric only
     *  - OTP only
     *  - Biometric + OTP
     */
    public String buildAuthRequest(
            MosipCryptoService.EncryptionResult encryptionResult,
            String transactionId,
            boolean hasBiometrics,
            boolean hasOtp
    ) throws JsonProcessingException {

        if (encryptionResult == null) {

            throw new IllegalArgumentException(
                    "Encryption result is null"
            );
        }

        if (!hasBiometrics && !hasOtp) {

            throw new IllegalArgumentException(
                    "At least one authentication method is required"
            );
        }

        ObjectNode authRequest =
                objectMapper.createObjectNode();

        // ------------------------------------------------------------
        // Basic request information
        // ------------------------------------------------------------

        authRequest.put(
                "id",
                MosipConfig.AUTH_ID
        );

        authRequest.put(
                "version",
                MosipConfig.AUTH_VERSION
        );

        authRequest.put(
                "requestTime",
                getCurrentUtcTimestamp()
        );

        AppLogger.d(
                "DEBUG: AuthRequestBuilder transaction ID = "
                        + MosipConfig.TRANSACTION_ID
        );

        AppLogger.d(
                "DEBUG: AuthRequestBuilder transaction ID length = "
                        + MosipConfig.TRANSACTION_ID.length()
        );

        authRequest.put(
                "transactionID",
                MosipConfig.TRANSACTION_ID
        );

        authRequest.put(
                "consentObtained",
                true
        );

        authRequest.put(
                "individualId",
                MosipConfig.INDIVIDUAL_ID
        );

        authRequest.put(
                "individualIdType",
                MosipConfig.INDIVIDUAL_ID_TYPE
        );

        // ------------------------------------------------------------
        // Requested authentication
        // ------------------------------------------------------------

        ObjectNode requestedAuth =
                objectMapper.createObjectNode();

        requestedAuth.put(
                "bio",
                hasBiometrics
        );

        requestedAuth.put(
                "otp",
                hasOtp
        );

        requestedAuth.put(
                "demo",
                false
        );

        requestedAuth.put(
                "pin",
                false
        );

        authRequest.set(
                "requestedAuth",
                requestedAuth
        );

        // ------------------------------------------------------------
        // Environment
        // ------------------------------------------------------------

        authRequest.put(
                "env",
                MosipConfig.ENVIRONMENT
        );

        authRequest.put(
                "domainUri",
                MosipConfig.MOSIP_BASE_URL
        );

        // ------------------------------------------------------------
        // Encrypted request fields
        // ------------------------------------------------------------

        authRequest.put(
                "request",
                encryptionResult.encryptedIdentity
        );

        authRequest.put(
                "requestSessionKey",
                encryptionResult.encryptedSessionKey
        );

        authRequest.put(
                "requestHMAC",
                encryptionResult.requestHmac
        );

        authRequest.put(
                "thumbprint",
                encryptionResult.thumbprint
        );

        AppLogger.d(
                "DEBUG: Auth request env = "
                        + authRequest.path("env").asText()
        );

        AppLogger.d(
                "DEBUG: Config environment = "
                        + MosipConfig.ENVIRONMENT
        );

        AppLogger.d(
                "DEBUG: Requested biometric authentication = "
                        + hasBiometrics
        );

        AppLogger.d(
                "DEBUG: Requested OTP authentication = "
                        + hasOtp
        );

        return objectMapper.writeValueAsString(
                authRequest
        );
    }

    // ============================================================
    // UTC TIMESTAMP
    // ============================================================

    private String getCurrentUtcTimestamp() {

        return java.time.Instant
                .now()
                .toString();
    }
}