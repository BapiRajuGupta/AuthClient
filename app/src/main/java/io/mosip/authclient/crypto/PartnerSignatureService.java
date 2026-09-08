package io.mosip.authclient.crypto;

import android.content.Context;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import io.mosip.authclient.config.MosipConfig;
import io.mosip.authclient.util.AppLogger;

public class PartnerSignatureService {

    private final Context context;

    public PartnerSignatureService(
            Context context) {

        this.context =
                context.getApplicationContext();
    }

    public String sign(
            String requestJson
    ) throws Exception {

        AppLogger.section(
                "SIGNING AUTH REQUEST"
        );

        KeyStore keyStore =
                KeyStore.getInstance(
                        "PKCS12"
                );

        try (InputStream inputStream =
                     context
                             .getAssets()
                             .open(
                                     MosipConfig.PARTNER_P12_FILE
                             )) {

            keyStore.load(
                    inputStream,
                    MosipConfig
                            .PARTNER_P12_PASSWORD
                            .toCharArray()
            );
        }

        String privateKeyAlias = null;

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

        if (privateKeyAlias == null) {

            throw new Exception(
                    "No private key found in partner P12"
            );
        }

        KeyStore.PrivateKeyEntry keyEntry =
                (KeyStore.PrivateKeyEntry)
                        keyStore.getEntry(
                                privateKeyAlias,
                                new KeyStore.PasswordProtection(
                                        MosipConfig
                                                .PARTNER_P12_PASSWORD
                                                .toCharArray()
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