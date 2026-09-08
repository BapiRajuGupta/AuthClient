package io.mosip.authclient.crypto;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;
import javax.crypto.spec.SecretKeySpec;

import io.mosip.authclient.util.AppLogger;

import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;

public class MosipCryptoService {

    private static final String AES = "AES";

    private static final String AES_TRANSFORMATION =
            "AES/GCM/NoPadding";

    private static final String RSA_TRANSFORMATION =
            "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private static final int GCM_TAG_LENGTH = 128;

    // ============================================================
    // AES SESSION KEY
    // ============================================================

    public SecretKey generateAesKey()
            throws Exception {

        KeyGenerator keyGenerator =
                KeyGenerator.getInstance(AES);

        keyGenerator.init(256);

        return keyGenerator.generateKey();
    }

    // ============================================================
    // AES/GCM
    //
    // MOSIP FORMAT:
    //
    // encryptedData + IV
    //
    // IV is 16 bytes because the MOSIP CryptoCore implementation
    // uses cipher.getBlockSize().
    // ============================================================

    public byte[] symmetricEncrypt(
            byte[] data,
            SecretKey secretKey
    ) throws Exception {

        if (secretKey == null) {
            throw new InvalidKeyException(
                    "Secret key is null"
            );
        }

        if (data == null || data.length == 0) {
            throw new IllegalArgumentException(
                    "Data is empty"
            );
        }

        Cipher cipher =
                Cipher.getInstance(
                        AES_TRANSFORMATION
                );

        byte[] iv =
                new byte[cipher.getBlockSize()];

        SecureRandom secureRandom =
                new SecureRandom();

        secureRandom.nextBytes(iv);

        GCMParameterSpec gcmParameterSpec =
                new GCMParameterSpec(
                        GCM_TAG_LENGTH,
                        iv
                );

        SecretKeySpec keySpec =
                new SecretKeySpec(
                        secretKey.getEncoded(),
                        AES
                );

        cipher.init(
                Cipher.ENCRYPT_MODE,
                keySpec,
                gcmParameterSpec
        );

        byte[] encryptedData =
                cipher.doFinal(data);

        byte[] output =
                new byte[
                        encryptedData.length
                                + iv.length
                        ];

        System.arraycopy(
                encryptedData,
                0,
                output,
                0,
                encryptedData.length
        );

        System.arraycopy(
                iv,
                0,
                output,
                encryptedData.length,
                iv.length
        );

        return output;
    }

    // ============================================================
    // RSA / OAEP
    // ============================================================

    public byte[] asymmetricEncrypt(
            byte[] data,
            PublicKey publicKey
    ) throws Exception {

        if (publicKey == null) {
            throw new InvalidKeyException(
                    "Public key is null"
            );
        }

        if (data == null || data.length == 0) {
            throw new IllegalArgumentException(
                    "Data is empty"
            );
        }

        Cipher cipher =
                Cipher.getInstance(
                        RSA_TRANSFORMATION
                );

        OAEPParameterSpec oaepParameterSpec =
                new OAEPParameterSpec(
                        "SHA-256",
                        "MGF1",
                        MGF1ParameterSpec.SHA256,
                        PSpecified.DEFAULT
                );

        cipher.init(
                Cipher.ENCRYPT_MODE,
                publicKey,
                oaepParameterSpec
        );

        return cipher.doFinal(data);
    }

    // ============================================================
    // SHA-256 HEX
    // ============================================================

    public String sha256Hex(
            byte[] data
    ) throws Exception {

        MessageDigest messageDigest =
                MessageDigest.getInstance(
                        "SHA-256"
                );

        byte[] hash =
                messageDigest.digest(data);

        StringBuilder hex =
                new StringBuilder();

        for (byte b : hash) {

            hex.append(
                    String.format(
                            "%02X",
                            b
                    )
            );
        }

        return hex.toString();
    }

    // ============================================================
    // CERTIFICATE THUMBPRINT
    // ============================================================

    public String certificateThumbprint(
            byte[] certificateBytes
    ) throws Exception {

        byte[] hash =
                MessageDigest
                        .getInstance("SHA-256")
                        .digest(
                                certificateBytes
                        );

        return android.util.Base64.encodeToString(
                hash,
                android.util.Base64.NO_WRAP
                        | android.util.Base64.URL_SAFE
        );
    }

    public EncryptionResult encryptIdentityRequest(
            String identityRequest,
            X509Certificate certificate
    ) throws Exception {

        AppLogger.section(
                "ENCRYPTING IDENTITY REQUEST"
        );

        AppLogger.d("DEBUG : identityRequest : " + identityRequest);

        EncryptionResult result =
                new EncryptionResult();

        // ------------------------------------------------------------
        // Generate AES session key
        // ------------------------------------------------------------

        SecretKey secretKey =
                generateAesKey();

        AppLogger.info(
                "AES session key generated"
        );

        // ------------------------------------------------------------
        // Encrypt identity request using AES
        // ------------------------------------------------------------

        byte[] encryptedIdentity =
                symmetricEncrypt(
                        identityRequest.getBytes(
                                StandardCharsets.UTF_8
                        ),
                        secretKey
                );

        result.encryptedIdentity =
                Base64.encodeToString(
                        encryptedIdentity,
                        Base64.URL_SAFE
                                | Base64.NO_WRAP
                );

        // ------------------------------------------------------------
// DEBUG: Verify AES encryption locally
// ------------------------------------------------------------

        byte[] decryptedIdentity =
                symmetricDecrypt(
                        encryptedIdentity,
                        secretKey
                );

        String decryptedIdentityRequest =
                new String(
                        decryptedIdentity,
                        StandardCharsets.UTF_8
                );

        AppLogger.d(
                "DEBUG: Local AES decrypt successful = "
                        + identityRequest.equals(
                        decryptedIdentityRequest
                )
        );

        AppLogger.d(
                "DEBUG: Original identity length = "
                        + identityRequest.length()
        );

        AppLogger.d(
                "DEBUG: Decrypted identity length = "
                        + decryptedIdentityRequest.length()
        );

        AppLogger.success(
                "Identity encrypted successfully"
        );

        // ------------------------------------------------------------
        // Encrypt AES session key using MOSIP certificate
        // ------------------------------------------------------------

        byte[] encryptedSessionKey =
                asymmetricEncrypt(
                        secretKey.getEncoded(),
                        certificate.getPublicKey()
                );

        result.encryptedSessionKey =
                Base64.encodeToString(
                        encryptedSessionKey,
                        Base64.URL_SAFE
                                | Base64.NO_WRAP
                );

        AppLogger.success(
                "Session key encrypted successfully"
        );

        // ------------------------------------------------------------
        // Generate HMAC exactly like Windows MOSIP client
        // ------------------------------------------------------------

        byte[] identityBytes =
                identityRequest.getBytes(
                        StandardCharsets.UTF_8
                );

        AppLogger.d(
                "DEBUG: Identity bytes length = "
                        + identityBytes.length
        );

        String digest =
                sha256Hex(identityBytes);

        AppLogger.d(
                "DEBUG: Identity SHA-256 digest length = "
                        + digest.length()
        );

        // Encrypt the HEX digest using the SAME AES session key

        byte[] encryptedHmac =
                symmetricEncrypt(
                        digest.getBytes(
                                StandardCharsets.UTF_8
                        ),
                        secretKey
                );

        result.requestHmac =
                Base64.encodeToString(
                        encryptedHmac,
                        Base64.URL_SAFE
                                | Base64.NO_WRAP
                );

        AppLogger.success(
                "Request HMAC generated successfully"
        );

        // ------------------------------------------------------------
        // Certificate thumbprint
        // ------------------------------------------------------------

        result.thumbprint =
                certificateThumbprint(
                        certificate.getEncoded()
                );

        AppLogger.success(
                "Certificate thumbprint generated"
        );

        return result;
    }

    public static class EncryptionResult {

        public String encryptedIdentity;
        public String encryptedSessionKey;
        public String requestHmac;
        public String thumbprint;
    }

    private byte[] symmetricDecrypt(
            byte[] encryptedData,
            SecretKey secretKey
    ) throws Exception {

        if (encryptedData == null
                || encryptedData.length <= 16) {

            throw new IllegalArgumentException(
                    "Encrypted data is invalid"
            );
        }

        byte[] iv =
                new byte[16];

        byte[] cipherText =
                new byte[
                        encryptedData.length - 16
                        ];

        System.arraycopy(
                encryptedData,
                encryptedData.length - 16,
                iv,
                0,
                16
        );

        System.arraycopy(
                encryptedData,
                0,
                cipherText,
                0,
                cipherText.length
        );

        Cipher cipher =
                Cipher.getInstance(
                        AES_TRANSFORMATION
                );

        GCMParameterSpec gcmParameterSpec =
                new GCMParameterSpec(
                        GCM_TAG_LENGTH,
                        iv
                );

        SecretKeySpec keySpec =
                new SecretKeySpec(
                        secretKey.getEncoded(),
                        AES
                );

        cipher.init(
                Cipher.DECRYPT_MODE,
                keySpec,
                gcmParameterSpec
        );

        return cipher.doFinal(
                cipherText
        );
    }


}