package io.mosip.authclient.sbi;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.util.Base64;
import android.util.Log;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import io.mosip.authclient.config.MosipConfig;
import io.mosip.authclient.dto.CaptureDeviceDetail;
import io.mosip.authclient.dto.CaptureRequest;
import io.mosip.authclient.dto.DeviceInfoPayload;
import io.mosip.authclient.dto.DeviceInfoResponse;
import io.mosip.authclient.dto.DigitalIdPayload;
import io.mosip.authclient.dto.DiscoverResponse;
import io.mosip.authclient.util.AppLogger;
import io.mosip.authclient.util.JwtUtils;

public class SbiService {

    private static final int REQUEST_DISCOVERY = 100;
    private static final int REQUEST_INFO = 101;
    private static final int REQUEST_CAPTURE = 102;

    private final Activity activity;
    private final ObjectMapper objectMapper;

    private String sbiPackageName;
    private String sbiActivityName;

    public SbiService(
            Activity activity,
            ObjectMapper objectMapper
    ) {
        this.activity = activity;
        this.objectMapper = objectMapper;
    }

    // ============================================================
    // SBI APPLICATION
    // ============================================================

    private boolean findSbiApplication() {

        Intent intent =
                new Intent(
                        MosipConfig.SBI_DISCOVERY_ACTION
                );

        PackageManager packageManager =
                activity.getPackageManager();

        List<ResolveInfo> activities =
                packageManager.queryIntentActivities(
                        intent,
                        PackageManager.MATCH_DEFAULT_ONLY
                );

        if (activities.isEmpty()) {

            AppLogger.warning(
                    "No SBI application found"
            );

            return false;
        }

        ResolveInfo activityInfo =
                activities.get(0);

        sbiPackageName =
                activityInfo
                        .activityInfo
                        .applicationInfo
                        .packageName;

        sbiActivityName =
                activityInfo
                        .activityInfo
                        .name;

        AppLogger.success(
                "SBI application found"
        );

        return true;
    }

    // ============================================================
    // DISCOVERY
    // ============================================================

    public void discover(
            String biometricType
    ) {

        try {

            AppLogger.section(
                    "SBI DISCOVERY"
            );

            if (!findSbiApplication()) {

                showToast(
                        "Biometric device application is unavailable."
                );

                return;
            }

            Intent intent =
                    new Intent(
                            MosipConfig.SBI_DISCOVERY_ACTION
                    );

            intent.setComponent(
                    new ComponentName(
                            sbiPackageName,
                            sbiActivityName
                    )
            );

            String request =
                    "{\"type\":\""
                            + biometricType
                            + "\"}";

            AppLogger.step(
                    "Discovering "
                            + biometricType
            );

            intent.putExtra(
                    "input",
                    request.getBytes(
                            StandardCharsets.UTF_8
                    )
            );

            activity.startActivityForResult(
                    intent,
                    REQUEST_DISCOVERY
            );

        } catch (Exception e) {

            AppLogger.e(
                    "SBI discovery failed",
                    e
            );

            showToast(
                    "Unable to discover biometric device."
            );
        }
    }

    // ============================================================
    // INFO
    // ============================================================

    public void requestInfo(
            DiscoverResponse sbi
    ) {

        if (sbi == null) {

            showToast(
                    "Biometric device information is unavailable."
            );

            return;
        }

        try {

            AppLogger.section(
                    "SBI DEVICE INFO"
            );

            String action =
                    sbi.getCallbackId()
                            + ".Info";

            Intent intent =
                    new Intent();

            intent.setAction(action);

            intent.setComponent(
                    new ComponentName(
                            sbiPackageName,
                            sbiActivityName
                    )
            );

            AppLogger.step(
                    "Requesting device information"
            );

            activity.startActivityForResult(
                    intent,
                    REQUEST_INFO
            );

        } catch (Exception e) {

            AppLogger.e(
                    "SBI info request failed",
                    e
            );

            showToast(
                    "Unable to retrieve biometric device information."
            );
        }
    }

    // ============================================================
    // CAPTURE
    // ============================================================

    public void capture(
            String modality,
            DiscoverResponse sbi,
            DeviceInfoPayload info,
            String previousHash,
            String transactionId,
            int fingerCount,
            String irisType
    ) {

        if (sbi == null || info == null) {

            showToast(
                    modality
                            + " biometric device is unavailable."
            );

            return;
        }

        try {

            AppLogger.section(
                    "SBI CAPTURE"
            );

            String action =
                    sbi.getCallbackId()
                            + ".Capture";

            Intent intent =
                    new Intent();

            intent.setAction(action);

            intent.setComponent(
                    new ComponentName(
                            sbiPackageName,
                            sbiActivityName
                    )
            );

            CaptureRequest request =
                    new CaptureRequest();

            request.setEnv(
                    info.getEnv()
            );

            request.setPurpose(
                    info.getPurpose()
            );

            request.setSpecVersion(
                    info.getSpecVersion().get(0)
            );

            request.setTimeout(
                    MosipConfig.CAPTURE_TIMEOUT
            );

            request.setCaptureTime(
                    getCurrentUtcTimestamp()
            );

            /*
             * Keep the currently working values.
             */
            request.setDomainUri(
                    MosipConfig.DOMAIN_URI
            );

            request.setTransactionId(
                    transactionId
            );

            CaptureDeviceDetail bio =
                    new CaptureDeviceDetail();

            bio.setType(
                    modality
            );

            configureBiometricRequest(
                    bio,
                    modality,
                    fingerCount,
                    irisType
            );

            bio.setRequestedScore(
                    40
            );

            bio.setDeviceId(
                    info.getDeviceId()
            );

            bio.setDeviceSubId(
                    info.getDeviceSubId().get(0)
            );

            bio.setPreviousHash(
                    previousHash
            );

            List<CaptureDeviceDetail> bioList =
                    new ArrayList<>();

            bioList.add(bio);

            request.setBio(bioList);

            request.setCustomOpts(null);

            byte[] input =
                    objectMapper.writeValueAsBytes(
                            request
                    );

            AppLogger.step(
                    "Sending "
                            + modality
                            + " capture request"
            );

            /*
             * Do NOT log the complete request.
             * It contains biometric-related data.
             */

            intent.putExtra(
                    "input",
                    input
            );

            activity.startActivityForResult(
                    intent,
                    REQUEST_CAPTURE
            );

        } catch (Exception e) {

            AppLogger.e(
                    "SBI capture request failed for "
                            + modality,
                    e
            );

            showToast(
                    "Unable to start "
                            + modality
                            + " biometric capture."
            );
        }
    }

    // ============================================================
    // CAPTURE RESPONSE
    // ============================================================

    public List<JsonNode> parseCaptureResponse(
            Uri responseUri
    ) throws Exception {

        if (responseUri == null) {

            throw new Exception(
                    "Capture response URI is missing"
            );
        }

        AppLogger.step(
                "Reading SBI capture response"
        );

        InputStream inputStream =
                activity
                        .getContentResolver()
                        .openInputStream(
                                responseUri
                        );

        if (inputStream == null) {

            throw new Exception(
                    "Unable to open SBI response"
            );
        }

        byte[] response =
                readBytes(inputStream);

        String responseText =
                new String(
                        response,
                        StandardCharsets.UTF_8
                );

        JsonNode root =
                objectMapper.readTree(
                        responseText
                );

        AppLogger.d("CaptureResponse : " + responseText);

        List<JsonNode> biometricObjects =
                new ArrayList<>();

        if (root.isArray()) {

            for (JsonNode responseObject : root) {

                JsonNode biometrics =
                        responseObject.get(
                                "biometrics"
                        );

                if (biometrics != null
                        && biometrics.isArray()) {

                    for (JsonNode biometric :
                            biometrics) {

                        biometricObjects.add(
                                biometric
                        );
                    }
                }
            }

        } else {

            JsonNode biometrics =
                    root.get("biometrics");

            if (biometrics != null
                    && biometrics.isArray()) {

                for (JsonNode biometric :
                        biometrics) {

                    biometricObjects.add(
                            biometric
                    );
                }
            }
        }

        if (biometricObjects.isEmpty()) {

            throw new Exception(
                    "SBI response contains no biometrics"
            );
        }

        AppLogger.success(
                "SBI capture response received"
        );

        AppLogger.d(
                "Biometric objects received: "
                        + biometricObjects.size()
        );

        return biometricObjects;
    }

    // ============================================================
    // DISCOVERY DIGITAL ID
    // ============================================================

    public DigitalIdPayload decodeDiscoveryDigitalId(
            String digitalId
    ) throws Exception {

        byte[] decoded =
                android.util.Base64.decode(
                        digitalId,
                        android.util.Base64.DEFAULT
                );

        return objectMapper.readValue(
                decoded,
                DigitalIdPayload.class
        );
    }

    // ============================================================
    // DEVICE INFO RESPONSE
    // ============================================================

    public DeviceInfoResponse parseInfoResponse(
            byte[] response
    ) throws Exception {

        List<DeviceInfoResponse> responses =
                objectMapper.readValue(
                        response,
                        new TypeReference<
                                List<DeviceInfoResponse>
                                >() {}
                );

        if (responses.isEmpty()) {

            throw new Exception(
                    "Empty SBI info response"
            );
        }

        return responses.get(0);
    }

    public DeviceInfoPayload decodeDeviceInfo(
            DeviceInfoResponse response
    ) throws Exception {

        if (response == null) {

            throw new Exception(
                    "Device info response is null"
            );
        }

        if (response.getError() != null
                && !"0".equals(
                response
                        .getError()
                        .getErrorCode()
        )) {

            throw new Exception(
                    response
                            .getError()
                            .getErrorInfo()
            );
        }

        byte[] payload =
                JwtUtils.getPayload(
                        response.getDeviceInfo()
                );

        if (payload == null) {

            throw new Exception(
                    "Unable to decode device information"
            );
        }

        return objectMapper.readValue(
                payload,
                DeviceInfoPayload.class
        );
    }

    // ============================================================
    // BIOMETRIC REQUEST CONFIGURATION
    // ============================================================

    private void configureBiometricRequest(
            CaptureDeviceDetail bio,
            String modality,
            int fingerCount,
            String irisType
    ) {

        if ("Finger".equals(modality)) {

            int count =
                    Math.max(
                            1,
                            fingerCount
                    );

            bio.setCount(
                    String.valueOf(count)
            );

            String[] subTypes =
                    new String[count];

            for (int i = 0; i < count; i++) {

                subTypes[i] = "UNKNOWN";
            }

            bio.setBioSubType(
                    subTypes
            );

        } else if ("Iris".equals(modality)) {

            int count =
                    "Both Iris".equals(irisType)
                            ? 2
                            : 1;

            bio.setCount(
                    String.valueOf(count)
            );

            String[] subTypes =
                    new String[count];

            for (int i = 0; i < count; i++) {

                subTypes[i] = "UNKNOWN";
            }

            bio.setBioSubType(
                    subTypes
            );

        } else if ("Face".equals(modality)) {

            bio.setCount("1");

            bio.setBioSubType(
                    new String[]{
                            "UNKNOWN"
                    }
            );
        }
    }

    // ============================================================
    // HELPERS
    // ============================================================

    private byte[] readBytes(
            InputStream inputStream
    ) throws Exception {

        try (InputStream input =
                     inputStream) {

            java.io.ByteArrayOutputStream buffer =
                    new java.io.ByteArrayOutputStream();

            byte[] data =
                    new byte[4096];

            int bytesRead;

            while (
                    (bytesRead =
                            input.read(data))
                            != -1
            ) {

                buffer.write(
                        data,
                        0,
                        bytesRead
                );
            }

            return buffer.toByteArray();
        }
    }

    private String getCurrentUtcTimestamp() {

        java.text.SimpleDateFormat formatter =
                new java.text.SimpleDateFormat(
                        "yyyy-MM-dd'T'HH:mm:ss'Z'",
                        java.util.Locale.US
                );

        formatter.setTimeZone(
                java.util.TimeZone.getTimeZone(
                        "UTC"
                )
        );

        return formatter.format(
                new java.util.Date()
        );
    }

    private void showToast(
            String message
    ) {

        activity.runOnUiThread(() ->
                android.widget.Toast.makeText(
                        activity,
                        message,
                        android.widget.Toast.LENGTH_LONG
                ).show()
        );
    }

    // ============================================================
// CAPTURE RESPONSE
// ============================================================

    public List<JsonNode> readCaptureResponse(
            Uri responseUri
    ) throws Exception {

        if (responseUri == null) {

            throw new IllegalArgumentException(
                    "Capture response URI is null"
            );
        }

        AppLogger.section(
                "SBI CAPTURE RESPONSE"
        );

        AppLogger.step(
                "Reading capture response"
        );

        InputStream inputStream =
                activity
                        .getContentResolver()
                        .openInputStream(
                                responseUri
                        );

        if (inputStream == null) {

            throw new Exception(
                    "Unable to open SBI capture response"
            );
        }

        byte[] response =
                readBytes(
                        inputStream
                );

        String responseText =
                new String(
                        response,
                        StandardCharsets.UTF_8
                );

        AppLogger.step(
                "SBI capture response received"
        );

        AppLogger.info(
                "Response length: "
                        + responseText.length()
        );

        JsonNode root =
                objectMapper.readTree(
                        responseText
                );

        List<JsonNode> biometricObjects =
                new ArrayList<>();

        /*
         * Android Mock SBI can return:
         *
         * [
         *   {
         *     "biometrics": [...]
         *   }
         * ]
         *
         * or:
         *
         * {
         *   "biometrics": [...]
         * }
         */

        if (root.isArray()) {

            AppLogger.info(
                    "SBI response format: ARRAY"
            );

            for (JsonNode responseObject : root) {

                JsonNode responseBiometrics =
                        responseObject.get(
                                "biometrics"
                        );

                if (responseBiometrics != null
                        && responseBiometrics.isArray()) {

                    for (JsonNode biometric :
                            responseBiometrics) {

                        biometricObjects.add(
                                biometric
                        );
                    }
                }
            }

        } else {

            AppLogger.info(
                    "SBI response format: OBJECT"
            );

            JsonNode responseBiometrics =
                    root.get(
                            "biometrics"
                    );

            if (responseBiometrics != null
                    && responseBiometrics.isArray()) {

                for (JsonNode biometric :
                        responseBiometrics) {

                    biometricObjects.add(
                            biometric
                    );
                }
            }
        }

        AppLogger.info(
                "Biometric objects received: "
                        + biometricObjects.size()
        );

        return biometricObjects;
    }

    // ============================================================
// DISCOVERY RESPONSE
// ============================================================

    public DiscoverResponse parseDiscoveryResponse(
            byte[] response,
            String modality
    ) throws Exception {

        if (response == null
                || response.length == 0) {

            throw new Exception(
                    "Empty SBI discovery response"
            );
        }

        AppLogger.section(
                "SBI DISCOVERY RESPONSE"
        );

        AppLogger.step(
                "Processing "
                        + modality
                        + " discovery response"
        );

        List<DiscoverResponse> responses =
                objectMapper.readValue(
                        response,
                        new TypeReference<
                                List<DiscoverResponse>
                                >() {}
                );

        if (responses.isEmpty()) {

            throw new Exception(
                    "No biometric device found for "
                            + modality
            );
        }

        /*
         * The current application expects the first
         * SBI returned for each modality.
         *
         * Keep this behavior unchanged.
         */
        DiscoverResponse sbi =
                responses.get(0);

        // --------------------------------------------------------
        // Decode digitalId
        // --------------------------------------------------------

        if (sbi.getDigitalId() != null
                && !sbi.getDigitalId().isEmpty()) {

            byte[] decoded =
                    android.util.Base64.decode(
                            sbi.getDigitalId(),
                            android.util.Base64.DEFAULT
                    );

            DigitalIdPayload digitalId =
                    objectMapper.readValue(
                            decoded,
                            DigitalIdPayload.class
                    );

            /*
             * Keep the decoded Digital ID inside
             * DiscoverResponse, as the existing code does.
             */
            sbi.setDecodedDigitalId(
                    digitalId
            );

            AppLogger.success(
                    modality
                            + " SBI discovered"
            );

            AppLogger.info(
                    "Device ID: "
                            + sbi.getDeviceId()
            );

            AppLogger.info(
                    "Callback ID: "
                            + sbi.getCallbackId()
            );

            AppLogger.info(
                    "Device Status: "
                            + sbi.getDeviceStatus()
            );

            AppLogger.info(
                    "Digital ID Serial: "
                            + digitalId.getSerialNo()
            );

            AppLogger.info(
                    "Digital ID Model: "
                            + digitalId.getModel()
            );

            AppLogger.info(
                    "Digital ID Type: "
                            + digitalId.getType()
            );

        } else {

            AppLogger.warning(
                    modality
                            + " SBI response does not contain digitalId"
            );
        }

        return sbi;
    }

    // ============================================================
// DEVICE INFO RESPONSE
// ============================================================

    public DeviceInfoPayload parseDeviceInfoResponse(
            byte[] response
    ) throws Exception {

        if (response == null || response.length == 0) {

            throw new Exception(
                    "Empty SBI device info response"
            );
        }

        AppLogger.section(
                "SBI DEVICE INFO RESPONSE"
        );

        AppLogger.step(
                "Processing device information response"
        );

        List<DeviceInfoResponse> responses =
                objectMapper.readValue(
                        response,
                        new TypeReference<
                                List<DeviceInfoResponse>
                                >() {}
                );

        if (responses.isEmpty()) {

            throw new Exception(
                    "Empty SBI device info response"
            );
        }

        DeviceInfoResponse infoResponse =
                responses.get(0);

        // --------------------------------------------------------
        // SBI error
        // --------------------------------------------------------

        if (infoResponse.getError() != null
                && !"0".equals(
                infoResponse
                        .getError()
                        .getErrorCode()
        )) {

            throw new Exception(
                    infoResponse
                            .getError()
                            .getErrorInfo()
            );
        }

        // --------------------------------------------------------
        // Decode deviceInfo JWT
        // --------------------------------------------------------

        byte[] payload =
                getJwtPayload(
                        infoResponse.getDeviceInfo()
                );

        if (payload == null) {

            throw new Exception(
                    "Unable to decode device information"
            );
        }

        DeviceInfoPayload info =
                objectMapper.readValue(
                        payload,
                        DeviceInfoPayload.class
                );

        AppLogger.success(
                "Device information received successfully"
        );

        AppLogger.info(
                "Device ID: "
                        + info.getDeviceId()
        );

        AppLogger.info(
                "Device Status: "
                        + info.getDeviceStatus()
        );

        AppLogger.info(
                "Firmware: "
                        + info.getFirmware()
        );

        return info;
    }

    // ============================================================
    // JWT PAYLOAD DECODER
    // ============================================================

    private byte[] getJwtPayload(
            String jwt) {

        try {

            String[] parts =
                    jwt.split("\\.");


            if (parts.length < 2) {

                throw new IllegalArgumentException(
                        "Invalid JWT"
                );
            }


            return Base64.decode(
                    parts[1],
                    Base64.URL_SAFE
            );

        } catch (Exception e) {

            AppLogger.error(
                    "JWT decode failed",
                    e
            );

            return null;
        }
    }
}