package io.mosip.authclient.config;

public final class MosipConfig {

    private MosipConfig() {
        // Utility class
    }

    // ============================================================
    // MOSIP
    // ============================================================

    public static final String MOSIP_BASE_URL =
            "https://api-internal.synergy.mosip.net";

    public static final String MISP_LICENSE_KEY =
            "83PokZqsLinumzEEVwNgFjIiISU364RF2RbybT0CRW24oRdhx6";

    public static final String PARTNER_ID =
            "730";

    public static final String PARTNER_API_KEY =
            "538440";

    public static final String ENVIRONMENT =
            "Production";

    public static final String DOMAIN_URI =
            MOSIP_BASE_URL;

    public static final String SPEC_VERSION =
            "0.9.5";

    // ============================================================
    // AUTH
    // ============================================================

    public static final String AUTH_ID =
            "mosip.identity.auth";

    public static final String AUTH_VERSION =
            "1.0";

    public static final String INDIVIDUAL_ID_TYPE =
            "UIN";

    public static final String TRANSACTION_ID =
            "1234567890";

    public static final String INDIVIDUAL_ID = "2057691840"; //"6187023954"; //"8103801431"; //5312659057;

    // ============================================================
    // AUTH MANAGER
    // ============================================================

    public static final String AUTH_MANAGER_URL =
            MOSIP_BASE_URL
                    + "/v1/authmanager/authenticate/clientidsecretkey";

    public static final String AUTH_MANAGER_CLIENT_ID =
            "mosip-regproc-client";

    public static final String AUTH_MANAGER_SECRET_KEY =
            "IwKVNHehKvzjhxHB";

    public static final String AUTH_MANAGER_APP_ID =
            "regproc";

    // ============================================================
    // CERTIFICATE
    // ============================================================

    public static final String CERTIFICATE_URL =
            MOSIP_BASE_URL
                    + "/idauthentication/v1/internal/getCertificate"
                    + "?applicationId=IDA"
                    + "&referenceId=PARTNER";

    // ============================================================
    // PARTNER P12
    // ============================================================

    public static final String PARTNER_P12_FILE =
            "partner.p12";

    public static final String PARTNER_P12_PASSWORD =
            "qwerty@123";

    public static final String PARTNER_P12_ALIAS =
            "730";

    // ============================================================
    // SBI
    // ============================================================

    public static final String SBI_DISCOVERY_ACTION =
            "io.sbi.device";

    public static final int DISCOVERY_REQUEST_CODE = 100;
    public static final int INFO_REQUEST_CODE = 101;
    public static final int CAPTURE_REQUEST_CODE = 102;

    public static final int CAPTURE_TIMEOUT = 10000;

    // ============================================================
    // AUTH URL
    // ============================================================

    public static final String AUTH_URL =
            MOSIP_BASE_URL
                    + "/idauthentication/v1/auth/"
                    + MISP_LICENSE_KEY
                    + "/"
                    + PARTNER_ID
                    + "/"
                    + PARTNER_API_KEY;

    public static final String OTP_URL =
            MOSIP_BASE_URL
                    + "/idauthentication/v1/otp/"
                    + MISP_LICENSE_KEY
                    + "/"
                    + PARTNER_ID
                    + "/"
                    + PARTNER_API_KEY;
}