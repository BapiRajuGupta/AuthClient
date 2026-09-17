package io.mosip.authclient.config;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class SecureSettingsStore {

    private static final String KEYSTORE_NAME =
            "AndroidKeyStore";

    private static final String KEY_ALIAS =
            "AuthClientSecureSettingsKey";

    private static final String TRANSFORMATION =
            "AES/GCM/NoPadding";

    private static final int GCM_TAG_LENGTH =
            128;

    private static final int GCM_IV_LENGTH =
            12;

    /**
     * Encrypt plain text using an AES key stored in Android Keystore.
     */
    public String encrypt(
            String plainText
    ) throws Exception {

        SecretKey secretKey =
                getOrCreateSecretKey();

        Cipher cipher =
                Cipher.getInstance(
                        TRANSFORMATION
                );

        cipher.init(
                Cipher.ENCRYPT_MODE,
                secretKey
        );

        byte[] iv =
                cipher.getIV();

        byte[] encrypted =
                cipher.doFinal(
                        plainText.getBytes(
                                StandardCharsets.UTF_8
                        )
                );

        // Store IV + encrypted data together.
        byte[] output =
                new byte[
                        iv.length + encrypted.length
                        ];

        System.arraycopy(
                iv,
                0,
                output,
                0,
                iv.length
        );

        System.arraycopy(
                encrypted,
                0,
                output,
                iv.length,
                encrypted.length
        );

        return Base64.encodeToString(
                output,
                Base64.NO_WRAP
        );
    }

    /**
     * Decrypt text using the AES key stored in Android Keystore.
     */
    public String decrypt(
            String encryptedText
    ) throws Exception {

        SecretKey secretKey =
                getOrCreateSecretKey();

        byte[] input =
                Base64.decode(
                        encryptedText,
                        Base64.NO_WRAP
                );

        if (input.length <= GCM_IV_LENGTH) {

            throw new Exception(
                    "Invalid encrypted settings data"
            );
        }

        byte[] iv =
                new byte[GCM_IV_LENGTH];

        System.arraycopy(
                input,
                0,
                iv,
                0,
                GCM_IV_LENGTH
        );

        byte[] encrypted =
                new byte[
                        input.length - GCM_IV_LENGTH
                        ];

        System.arraycopy(
                input,
                GCM_IV_LENGTH,
                encrypted,
                0,
                encrypted.length
        );

        Cipher cipher =
                Cipher.getInstance(
                        TRANSFORMATION
                );

        GCMParameterSpec parameterSpec =
                new GCMParameterSpec(
                        GCM_TAG_LENGTH,
                        iv
                );

        cipher.init(
                Cipher.DECRYPT_MODE,
                secretKey,
                parameterSpec
        );

        byte[] decrypted =
                cipher.doFinal(
                        encrypted
                );

        return new String(
                decrypted,
                StandardCharsets.UTF_8
        );
    }

    /**
     * Get the AES key from Android Keystore.
     *
     * If the key does not exist, create it.
     */
    private SecretKey getOrCreateSecretKey()
            throws Exception {

        KeyStore keyStore =
                KeyStore.getInstance(
                        KEYSTORE_NAME
                );

        keyStore.load(null);

        if (keyStore.containsAlias(KEY_ALIAS)) {

            KeyStore.SecretKeyEntry entry =
                    (KeyStore.SecretKeyEntry)
                            keyStore.getEntry(
                                    KEY_ALIAS,
                                    null
                            );

            if (entry == null) {

                throw new Exception(
                        "Unable to retrieve secure settings key"
                );
            }

            return entry.getSecretKey();
        }

        KeyGenerator keyGenerator =
                KeyGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_AES,
                        KEYSTORE_NAME
                );

        KeyGenParameterSpec keySpec =
                new KeyGenParameterSpec.Builder(
                        KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT
                                | KeyProperties.PURPOSE_DECRYPT
                )
                        .setBlockModes(
                                KeyProperties.BLOCK_MODE_GCM
                        )
                        .setEncryptionPaddings(
                                KeyProperties.ENCRYPTION_PADDING_NONE
                        )
                        .setKeySize(256)
                        .build();

        keyGenerator.init(
                keySpec
        );

        return keyGenerator.generateKey();
    }
}