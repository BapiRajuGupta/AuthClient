package io.mosip.authclient.crypto;

import android.content.Context;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;

import io.mosip.authclient.config.MosipConfig;
import io.mosip.authclient.config.SettingsStore;
import io.mosip.authclient.util.AppLogger;

public class PartnerSignatureService {

    private final Context context;
    private final SettingsStore settingsStore;

    public PartnerSignatureService(
            Context context) {

        this.context =
                context.getApplicationContext();

        this.settingsStore =
                new SettingsStore(
                        context,
                        new com.fasterxml.jackson.databind.ObjectMapper()
                );
    }

    public String sign(
            String requestJson
    ) throws Exception {

        AppLogger.section(
                "SIGNING AUTH REQUEST"
        );

        // ------------------------------------------------------------
        // Load current settings
        // ------------------------------------------------------------

        SettingsStore.Settings settings =
                settingsStore.load();

        String p12Password =
                settings.p12Password;

        String p12Alias =
                settings.p12Alias;

        // ------------------------------------------------------------
        // Load partner P12
        //
        // For now, continue loading the P12 from assets.
        // P12 file selection will be connected separately.
        // ------------------------------------------------------------

        Provider bouncyCastleProvider =
                new org.bouncycastle.jce.provider.BouncyCastleProvider();

        KeyStore keyStore =
                KeyStore.getInstance(
                        "PKCS12",
                        bouncyCastleProvider
                );

        InputStream inputStream;

        if (settings.p12Path != null
                && !settings.p12Path.trim().isEmpty()
                && !settings.p12Path.equals(
                MosipConfig.PARTNER_P12_FILE)) {

            File p12File =
                    new File(settings.p12Path);

            if (!p12File.exists()
                    || !p12File.isFile()) {

                throw new Exception(
                        "Configured P12 file not found"
                );
            }

            inputStream =
                    new FileInputStream(p12File);

        } else {

            inputStream =
                    context
                            .getAssets()
                            .open(
                                    MosipConfig.PARTNER_P12_FILE
                            );
        }

        try (InputStream p12InputStream = inputStream) {

            keyStore.load(
                    p12InputStream,
                    p12Password.toCharArray()
            );
        }

        // ------------------------------------------------------------
        // Find signing key
        // ------------------------------------------------------------

        String privateKeyAlias = null;

        // First try the alias configured in Settings.
        if (p12Alias != null
                && !p12Alias.trim().isEmpty()
                && keyStore.isKeyEntry(p12Alias)) {

            privateKeyAlias = p12Alias;

            AppLogger.d(
                    "Partner signing key loaded using configured alias"
            );
        }

        // Fallback to the first private-key entry.
        if (privateKeyAlias == null) {

            java.util.Enumeration<String> aliases =
                    keyStore.aliases();

            while (aliases.hasMoreElements()) {

                String alias =
                        aliases.nextElement();

                if (keyStore.isKeyEntry(alias)) {

                    privateKeyAlias = alias;

                    AppLogger.d(
                            "Partner signing key loaded"
                    );

                    break;
                }
            }
        }

        if (privateKeyAlias == null) {

            throw new Exception(
                    "No private key found in partner P12"
            );
        }

        // ------------------------------------------------------------
        // Get private key
        // ------------------------------------------------------------

        KeyStore.PrivateKeyEntry keyEntry =
                (KeyStore.PrivateKeyEntry)
                        keyStore.getEntry(
                                privateKeyAlias,
                                new KeyStore.PasswordProtection(
                                        p12Password.toCharArray()
                                )
                        );

        if (keyEntry == null) {

            throw new Exception(
                    "Unable to load partner private key"
            );
        }

        PrivateKey privateKey =
                keyEntry.getPrivateKey();

        X509Certificate certificate =
                (X509Certificate)
                        keyEntry.getCertificate();

        // ------------------------------------------------------------
        // Generate detached JWS
        // ------------------------------------------------------------

        JsonWebSignature jws =
                new JsonWebSignature();

        jws.setCertificateChainHeaderValue(
                new X509Certificate[]{
                        certificate
                }
        );

        jws.setAlgorithmHeaderValue(
                AlgorithmIdentifiers
                        .RSA_USING_SHA256
        );

        jws.setPayload(
                requestJson
        );

        jws.setKey(
                privateKey
        );

        jws.setDoKeyValidation(
                false
        );

        String detachedSignature =
                jws.getDetachedContentCompactSerialization();

        AppLogger.success(
                "Auth request signature generated"
        );

        AppLogger.d(
                "Detached JWS generated. Length: "
                        + detachedSignature.length()
        );

        // IMPORTANT:
        // Do not log the actual JWS.

        return detachedSignature;
    }
}