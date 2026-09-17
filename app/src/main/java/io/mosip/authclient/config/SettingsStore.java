package io.mosip.authclient.config;

import android.content.Context;
import android.content.SharedPreferences;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class SettingsStore {

    private static final String PREF_NAME =
            "auth_client_settings";

    private static final String SETTINGS_KEY =
            "settings";

    private final SharedPreferences preferences;
    private final ObjectMapper objectMapper;
    private final SecureSettingsStore secureSettingsStore;

    public SettingsStore(
            Context context,
            ObjectMapper objectMapper
    ) {

        this.objectMapper =
                objectMapper;

        Context appContext =
                context.getApplicationContext();

        this.preferences =
                appContext.getSharedPreferences(
                        PREF_NAME,
                        Context.MODE_PRIVATE
                );

        this.secureSettingsStore =
                new SecureSettingsStore();
    }

    /**
     * Save settings.
     *
     * Normal settings are stored normally.
     *
     * Sensitive settings are encrypted using
     * SecureSettingsStore before being stored.
     */
    public void save(
            Settings settings
    ) throws Exception {

        ObjectNode root =
                objectMapper.createObjectNode();

        // ------------------------------------------------------------
        // Normal settings
        // ------------------------------------------------------------

        root.put(
                "baseUrl",
                settings.baseUrl
        );

        root.put(
                "environment",
                settings.environment
        );

        root.put(
                "domainUri",
                settings.domainUri
        );

        root.put(
                "authManagerUrl",
                settings.authManagerUrl
        );

        root.put(
                "authManagerClientId",
                settings.authManagerClientId
        );

        root.put(
                "authManagerAppId",
                settings.authManagerAppId
        );

        root.put(
                "certificateUrl",
                settings.certificateUrl
        );

        root.put(
                "partnerId",
                settings.partnerId
        );

        root.put(
                "p12Path",
                settings.p12Path
        );

        root.put(
                "p12Alias",
                settings.p12Alias
        );

        // ------------------------------------------------------------
        // Sensitive settings
        // ------------------------------------------------------------

        root.put(
                "mispLicenseKey",
                secureSettingsStore.encrypt(
                        settings.mispLicenseKey
                )
        );

        root.put(
                "partnerApiKey",
                secureSettingsStore.encrypt(
                        settings.partnerApiKey
                )
        );

        root.put(
                "authManagerSecret",
                secureSettingsStore.encrypt(
                        settings.authManagerSecret
                )
        );

        root.put(
                "p12Password",
                secureSettingsStore.encrypt(
                        settings.p12Password
                )
        );

        // ------------------------------------------------------------
        // Store JSON
        // ------------------------------------------------------------

        String json =
                objectMapper.writeValueAsString(
                        root
                );

        preferences.edit()
                .putString(
                        SETTINGS_KEY,
                        json
                )
                .apply();
    }

    /**
     * Load saved settings.
     *
     * Sensitive values are decrypted using
     * the Android Keystore backed key.
     */
    public Settings load()
            throws Exception {

        String json =
                preferences.getString(
                        SETTINGS_KEY,
                        null
                );

        if (json == null
                || json.trim().isEmpty()) {

            return createDefaultSettings();
        }

        ObjectNode root =
                (ObjectNode)
                        objectMapper.readTree(
                                json
                        );

        Settings settings =
                new Settings();

        // ------------------------------------------------------------
        // Normal settings
        // ------------------------------------------------------------

        settings.baseUrl =
                root.path("baseUrl")
                        .asText(
                                MosipConfig.MOSIP_BASE_URL
                        );

        settings.environment =
                root.path("environment")
                        .asText(
                                MosipConfig.ENVIRONMENT
                        );

        settings.domainUri =
                root.path("domainUri")
                        .asText(
                                MosipConfig.DOMAIN_URI
                        );

        settings.authManagerUrl =
                root.path("authManagerUrl")
                        .asText(
                                MosipConfig.AUTH_MANAGER_URL
                        );

        settings.authManagerClientId =
                root.path("authManagerClientId")
                        .asText(
                                MosipConfig.AUTH_MANAGER_CLIENT_ID
                        );

        settings.authManagerAppId =
                root.path("authManagerAppId")
                        .asText(
                                MosipConfig.AUTH_MANAGER_APP_ID
                        );

        settings.certificateUrl =
                root.path("certificateUrl")
                        .asText(
                                MosipConfig.CERTIFICATE_URL
                        );

        settings.partnerId =
                root.path("partnerId")
                        .asText(
                                MosipConfig.PARTNER_ID
                        );

        settings.p12Path =
                root.path("p12Path")
                        .asText(
                                MosipConfig.PARTNER_P12_FILE
                        );

        settings.p12Alias =
                root.path("p12Alias")
                        .asText(
                                MosipConfig.PARTNER_P12_ALIAS
                        );

        // ------------------------------------------------------------
        // Sensitive settings
        // ------------------------------------------------------------

        settings.mispLicenseKey =
                decryptOrDefault(
                        root,
                        "mispLicenseKey",
                        MosipConfig.MISP_LICENSE_KEY
                );

        settings.partnerApiKey =
                decryptOrDefault(
                        root,
                        "partnerApiKey",
                        MosipConfig.PARTNER_API_KEY
                );

        settings.authManagerSecret =
                decryptOrDefault(
                        root,
                        "authManagerSecret",
                        MosipConfig.AUTH_MANAGER_SECRET_KEY
                );

        settings.p12Password =
                decryptOrDefault(
                        root,
                        "p12Password",
                        MosipConfig.PARTNER_P12_PASSWORD
                );

        return settings;
    }

    /**
     * Decrypt a sensitive setting.
     *
     * If the value is not present, use the default
     * value from MosipConfig.
     */
    private String decryptOrDefault(
            ObjectNode root,
            String fieldName,
            String defaultValue
    ) throws Exception {

        String encryptedValue =
                root.path(fieldName)
                        .asText("");

        if (encryptedValue == null
                || encryptedValue.trim().isEmpty()) {

            return defaultValue;
        }

        return secureSettingsStore.decrypt(
                encryptedValue
        );
    }

    /**
     * Default settings taken from MosipConfig.
     */
    private Settings createDefaultSettings() {

        Settings settings =
                new Settings();

        settings.baseUrl =
                MosipConfig.MOSIP_BASE_URL;

        settings.environment =
                MosipConfig.ENVIRONMENT;

        settings.domainUri =
                MosipConfig.DOMAIN_URI;

        settings.authManagerUrl =
                MosipConfig.AUTH_MANAGER_URL;

        settings.authManagerClientId =
                MosipConfig.AUTH_MANAGER_CLIENT_ID;

        settings.authManagerSecret =
                MosipConfig.AUTH_MANAGER_SECRET_KEY;

        settings.authManagerAppId =
                MosipConfig.AUTH_MANAGER_APP_ID;

        settings.certificateUrl =
                MosipConfig.CERTIFICATE_URL;

        settings.mispLicenseKey =
                MosipConfig.MISP_LICENSE_KEY;

        settings.partnerId =
                MosipConfig.PARTNER_ID;

        settings.partnerApiKey =
                MosipConfig.PARTNER_API_KEY;

        settings.p12Path =
                MosipConfig.PARTNER_P12_FILE;

        settings.p12Password =
                MosipConfig.PARTNER_P12_PASSWORD;

        settings.p12Alias =
                MosipConfig.PARTNER_P12_ALIAS;

        return settings;
    }

    /**
     * Settings model.
     *
     * UIN / UIN Type are intentionally NOT included.
     */
    public static class Settings {

        public String baseUrl;
        public String environment;
        public String domainUri;

        public String authManagerUrl;
        public String authManagerClientId;
        public String authManagerSecret;
        public String authManagerAppId;

        public String certificateUrl;

        public String mispLicenseKey;
        public String partnerId;
        public String partnerApiKey;

        public String p12Path;
        public String p12Password;
        public String p12Alias;
    }
}