package io.mosip.authclient;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import io.mosip.authclient.auth.AuthManagerService;
import io.mosip.authclient.auth.AuthRequestBuilder;
import io.mosip.authclient.auth.MosipAuthService;
import io.mosip.authclient.auth.OtpService;
import io.mosip.authclient.config.MosipConfig;
import io.mosip.authclient.crypto.CertificateService;
import io.mosip.authclient.crypto.MosipCryptoService;
import io.mosip.authclient.crypto.PartnerSignatureService;
import io.mosip.authclient.dto.DeviceInfoPayload;
import io.mosip.authclient.dto.DiscoverResponse;
import io.mosip.authclient.sbi.SbiService;
import io.mosip.authclient.util.AppLogger;

public class MainActivity extends AppCompatActivity {

    private static final int REQUEST_DISCOVERY = 100;
    private static final int REQUEST_INFO = 101;
    private static final int REQUEST_CAPTURE = 102;

    // ------------------------------------------------------------
    // UI
    // ------------------------------------------------------------

    private CheckBox fingerCheckBox;
    private CheckBox faceCheckBox;
    private CheckBox irisCheckBox;

    private Button discoverButton;
    private Button infoButton;
    private Button captureButton;
    private Button authButton;
    private Button requestOtpButton;
    private Button resetButton;

    private EditText otpEditText;

    private Spinner fingerCountSpinner;
    private Spinner irisTypeSpinner;


    // ------------------------------------------------------------
    // Discovered SBI devices
    // ------------------------------------------------------------

    private DiscoverResponse fingerSBI;
    private DiscoverResponse faceSBI;
    private DiscoverResponse irisSBI;


    // ------------------------------------------------------------
    // Device Info
    // ------------------------------------------------------------

    private DeviceInfoPayload fingerInfo;
    private DeviceInfoPayload faceInfo;
    private DeviceInfoPayload irisInfo;


    // ------------------------------------------------------------
    // Discovery / Info sequence indexes
    // ------------------------------------------------------------

    private int discoveryIndex = 0;
    private int infoIndex = 0;


    // ------------------------------------------------------------
    // Capture sequence
    // ------------------------------------------------------------

    private List<String> captureModalities =
            new ArrayList<>();
    private int captureIndex = 0;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final List<JsonNode> capturedBiometrics = new ArrayList<>();
    private String previousHash = "";

    private String combinedBiometrics;

    // Discovery order
    private final String[] discoveryTypes = {
            "Finger",
            "Face",
            "Iris"
    };

    private SbiService sbiService;
    private AuthManagerService authManagerService;
    private CertificateService certificateService;
    private MosipCryptoService mosipCryptoService;
    private AuthRequestBuilder authRequestBuilder;
    private PartnerSignatureService partnerSignatureService;
    private OtpService otpService;
    private MosipAuthService mosipAuthService;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);

        EdgeToEdge.enable(this);

        setContentView(R.layout.activity_main);

        sbiService =
                new SbiService(
                        this,
                        objectMapper
                );

        authManagerService =
                new AuthManagerService(
                        objectMapper
                );

        certificateService = new CertificateService(
                this,
                objectMapper,
                authManagerService
        );

        mosipCryptoService = new MosipCryptoService();

        authRequestBuilder = new AuthRequestBuilder(
                objectMapper
        );

        partnerSignatureService = new PartnerSignatureService(
                this
        );

        mosipAuthService = new MosipAuthService(this);

        otpService = new OtpService(
                this,
                objectMapper,
                authManagerService,
                partnerSignatureService
        );


        // --------------------------------------------------------
        // UI references
        // --------------------------------------------------------

        fingerCheckBox =
                findViewById(R.id.fingerCheckBox);

        faceCheckBox =
                findViewById(R.id.faceCheckBox);

        irisCheckBox =
                findViewById(R.id.irisCheckBox);

        fingerCountSpinner =
                findViewById(R.id.fingerCountSpinner);

        irisTypeSpinner =
                findViewById(R.id.irisTypeSpinner);

        discoverButton =
                findViewById(R.id.discoverButton);

        infoButton =
                findViewById(R.id.infoButton);

        captureButton =
                findViewById(R.id.captureButton);

        authButton =
                findViewById(R.id.authButton);

        resetButton =
                findViewById(R.id.resetButton);

        requestOtpButton =
                findViewById(R.id.requestOtpButton);

        otpEditText =
                findViewById(R.id.otpEditText);

        setupFingerCountSpinner();
        setupIrisTypeSpinner();


        // --------------------------------------------------------
        // Window insets
        // --------------------------------------------------------

        ViewCompat.setOnApplyWindowInsetsListener(
                findViewById(R.id.main),
                (v, insets) -> {

                    Insets systemBars =
                            insets.getInsets(
                                    WindowInsetsCompat.Type.systemBars()
                            );

                    v.setPadding(
                            systemBars.left,
                            systemBars.top,
                            systemBars.right,
                            systemBars.bottom
                    );

                    return insets;
                }
        );


        // --------------------------------------------------------
        // Discover button
        // --------------------------------------------------------

        discoverButton.setOnClickListener(
                new View.OnClickListener() {
                    @Override
                    public void onClick(View view) {

                        startDiscoverySequence();
                    }
                }
        );


        // --------------------------------------------------------
        // Info button
        // --------------------------------------------------------

        infoButton.setOnClickListener(
                new View.OnClickListener() {
                    @Override
                    public void onClick(View view) {

                        startInfoSequence();
                    }
                }
        );


        // --------------------------------------------------------
        // Capture button
        // --------------------------------------------------------

        captureButton.setOnClickListener(
                new View.OnClickListener() {
                    @Override
                    public void onClick(View view) {

                        startCapture();
                    }
                }
        );

        authButton.setOnClickListener(
                new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        startAuthentication();
                    }
                }
        );

        requestOtpButton.setOnClickListener(
                new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        requestOtp();
                    }
                }
        );


        // --------------------------------------------------------
        // Reset button
        // --------------------------------------------------------

        resetButton.setOnClickListener(
                new View.OnClickListener() {
                    @Override
                    public void onClick(View view) {

                        resetApplication();
                    }
                }
        );

        // Start SBI discovery automatically
        startDiscoverySequence();
    }


    // ============================================================
    // DISCOVERY
    // ============================================================

    private void startDiscoverySequence() {

        AppLogger.section(
                "================================"
        );

        AppLogger.section(
                "Starting Discovery sequence"
        );

        AppLogger.section(
                "================================"
        );

        discoveryIndex = 0;

        discoverNext();
    }


    private void discoverNext() {

        if (discoveryIndex >= discoveryTypes.length) {

            AppLogger.info(
                    "All Discovery requests completed"
            );

            // Start Info automatically
            startInfoSequence();

            return;
        }

        String type =
                discoveryTypes[discoveryIndex];

        discoverSBI(type);
    }

    private void discoverSBI(String biometricType) {

        if (sbiService == null) {

            AppLogger.error(
                    "SBI service is not initialized"
            );

            Toast.makeText(
                    this,
                    "Unable to access biometric device service.",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }

        sbiService.discover(
                biometricType
        );
    }


    // ============================================================
    // DEVICE INFO
    // ============================================================

    private void startInfoSequence() {

        if (fingerSBI == null
                && faceSBI == null
                && irisSBI == null) {

            Toast.makeText(
                    this,
                    "Discover SBI first",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }


        AppLogger.section(
                "================================"
        );

        AppLogger.section(
                "Starting Info sequence"
        );

        AppLogger.section(
                "================================"
        );


        infoIndex = 0;

        getNextDeviceInfo();
    }


    private void getNextDeviceInfo() {

        /*
         * Order:
         *
         * 0 -> Finger
         * 1 -> Face
         * 2 -> Iris
         */

        if (infoIndex == 0
                && fingerSBI != null) {

            getDeviceInfo(
                    fingerSBI
            );

            return;
        }


        if (infoIndex == 1
                && faceSBI != null) {

            getDeviceInfo(
                    faceSBI
            );

            return;
        }


        if (infoIndex == 2
                && irisSBI != null) {

            getDeviceInfo(
                    irisSBI
            );

            return;
        }


        // If current index has no device,
        // move to next one.

        infoIndex++;

        if (infoIndex < 3) {

            getNextDeviceInfo();

        } else {

            AppLogger.info(
                    "All Info requests completed"
            );

            Toast.makeText(
                    this,
                    "Discovery + Info completed",
                    Toast.LENGTH_LONG
            ).show();
        }
    }


    private void getDeviceInfo(DiscoverResponse sbi) {

        if (sbiService == null) {

            AppLogger.error(
                    "SBI service is not initialized"
            );

            Toast.makeText(
                    this,
                    "Unable to access biometric device service.",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }

        sbiService.requestInfo(sbi);
    }


    // ============================================================
    // CAPTURE
    // ============================================================

    private void startCapture() {

        captureModalities.clear();

        // Start a fresh authentication capture session
        capturedBiometrics.clear();
        previousHash = "";

        // --------------------------------------------------------
        // Determine selected modalities
        // --------------------------------------------------------

        if (fingerCheckBox.isChecked()) {
            captureModalities.add("Finger");
        }

        if (faceCheckBox.isChecked()) {
            captureModalities.add("Face");
        }

        if (irisCheckBox.isChecked()) {
            captureModalities.add("Iris");
        }

        if (captureModalities.isEmpty()) {

            AppLogger.warning(
                    "No biometric modality selected"
            );

            Toast.makeText(
                    this,
                    "Please select at least one biometric.",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }

        // --------------------------------------------------------
        // Validate required SBI information
        // --------------------------------------------------------

        for (String modality : captureModalities) {

            if ("Finger".equals(modality)
                    && (fingerSBI == null || fingerInfo == null)) {

                AppLogger.warning(
                        "Finger biometric selected but SBI information is unavailable"
                );

                Toast.makeText(
                        this,
                        "Finger biometric service is not available.",
                        Toast.LENGTH_LONG
                ).show();

                return;
            }

            if ("Face".equals(modality)
                    && (faceSBI == null || faceInfo == null)) {

                AppLogger.warning(
                        "Face biometric selected but SBI information is unavailable"
                );

                Toast.makeText(
                        this,
                        "Face biometric service is not available.",
                        Toast.LENGTH_LONG
                ).show();

                return;
            }

            if ("Iris".equals(modality)
                    && (irisSBI == null || irisInfo == null)) {

                AppLogger.warning(
                        "Iris biometric selected but SBI information is unavailable"
                );

                Toast.makeText(
                        this,
                        "Iris biometric service is not available.",
                        Toast.LENGTH_LONG
                ).show();

                return;
            }
        }

        // --------------------------------------------------------
        // Start capture sequence
        // --------------------------------------------------------

        captureIndex = 0;

        AppLogger.info(
                "Starting biometric capture sequence"
        );

        AppLogger.info(
                "Selected modalities: "
                        + captureModalities
        );

        captureNext();
    }


    private void captureNext() {

        if (captureIndex >= captureModalities.size()) {

            AppLogger.section(
                    "ALL CAPTURES COMPLETED"
            );

            AppLogger.step(
                    "Combining captured biometric responses"
            );

            combinedBiometrics =
                    combineCaptures();

            if (combinedBiometrics == null) {

                AppLogger.error(
                        "Failed to combine biometric responses"
                );

                Toast.makeText(
                        this,
                        "Unable to process biometric data. Please try again.",
                        Toast.LENGTH_LONG
                ).show();

                return;
            }

            AppLogger.success(
                    "All biometric captures processed successfully"
            );

            Toast.makeText(
                    this,
                    "Biometric capture completed.",
                    Toast.LENGTH_LONG
            ).show();

            AppLogger.success(
                    "Biometric capture complete. Ready for authentication."
            );

            return;
        }

        String modality =
                captureModalities.get(
                        captureIndex
                );

        AppLogger.step(
                "Starting "
                        + modality
                        + " biometric capture"
        );

        captureForModality(
                modality
        );
    }

    private String combineCaptures() {

        AppLogger.info(
                "Combining captured biometric data"
        );

        ObjectNode combined =
                objectMapper.createObjectNode();

        ArrayNode biometricsArray =
                objectMapper.createArrayNode();

        for (int i = 0;
             i < capturedBiometrics.size();
             i++) {

            JsonNode biometric =
                    capturedBiometrics.get(i);

            AppLogger.info(
                    "Adding biometric "
                            + (i + 1)
                            + " of "
                            + capturedBiometrics.size()
            );

            biometricsArray.add(
                    biometric
            );
        }

        combined.set(
                "biometrics",
                biometricsArray
        );

        try {

            String result =
                    objectMapper
                            .writerWithDefaultPrettyPrinter()
                            .writeValueAsString(
                                    combined
                            );

            AppLogger.info(
                    "Biometric data combined successfully"
            );

            return result;

        } catch (JsonProcessingException e) {

            AppLogger.error(
                    "Unable to create biometric request"
            );

            return null;
        }
    }

    private void captureForModality(
            String modality) {

        if (sbiService == null) {

            AppLogger.error(
                    "SBI service is not initialized"
            );

            Toast.makeText(
                    this,
                    "Unable to access biometric device service.",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }

        DiscoverResponse sbi;
        DeviceInfoPayload info;

        // --------------------------------------------------------
        // Select the SBI and device information
        // --------------------------------------------------------

        if ("Finger".equals(modality)) {

            sbi = fingerSBI;
            info = fingerInfo;

        } else if ("Face".equals(modality)) {

            sbi = faceSBI;
            info = faceInfo;

        } else if ("Iris".equals(modality)) {

            sbi = irisSBI;
            info = irisInfo;

        } else {

            AppLogger.error(
                    "Unsupported biometric modality: "
                            + modality
            );

            Toast.makeText(
                    this,
                    "Unsupported biometric type.",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }

        if (sbi == null || info == null) {

            AppLogger.warning(
                    modality
                            + " biometric device information is unavailable"
            );

            Toast.makeText(
                    this,
                    modality
                            + " biometric device is unavailable.",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }

        // --------------------------------------------------------
        // Read current UI selections
        // --------------------------------------------------------

        int fingerCount = 1;

        if (fingerCountSpinner != null
                && fingerCountSpinner.getSelectedItem() != null) {

            try {

                fingerCount =
                        Integer.parseInt(
                                fingerCountSpinner
                                        .getSelectedItem()
                                        .toString()
                        );

            } catch (NumberFormatException e) {

                AppLogger.warning(
                        "Invalid finger count. Using default value 1."
                );

                fingerCount = 1;
            }
        }

        String irisType = "Both Iris";

        if (irisTypeSpinner != null
                && irisTypeSpinner.getSelectedItem() != null) {

            irisType =
                    irisTypeSpinner
                            .getSelectedItem()
                            .toString();
        }

        AppLogger.step(
                "Starting "
                        + modality
                        + " biometric capture"
        );


        AppLogger.d(
                "DEBUG: SBI capture transaction ID = "
                        + MosipConfig.TRANSACTION_ID
        );

        AppLogger.d(
                "DEBUG: SBI capture modality = "
                        + modality
        );

        AppLogger.d(
                "DEBUG: SBI previousHash present = "
                        + (previousHash != null
                        && !previousHash.isEmpty())
        );

        sbiService.capture(
                modality,
                sbi,
                info,
                previousHash,
                MosipConfig.TRANSACTION_ID,
                fingerCount,
                irisType
        );
    }


    // ============================================================
    // ACTIVITY RESULT
    // ============================================================

    @Override
    protected void onActivityResult(
            int requestCode,
            int resultCode,
            Intent data) {

        super.onActivityResult(
                requestCode,
                resultCode,
                data
        );

        if (requestCode == REQUEST_DISCOVERY) {

            handleDiscoveryResult(
                    resultCode,
                    data
            );

            return;
        }

        if (requestCode == REQUEST_INFO) {

            handleInfoResult(
                    resultCode,
                    data
            );

            return;
        }

        if (requestCode == REQUEST_CAPTURE) {

            handleCaptureResult(
                    resultCode,
                    data
            );
        }
    }

    private void handleDiscoveryResult(
            int resultCode,
            Intent data) {

        if (resultCode != RESULT_OK
                || data == null
                || !data.hasExtra("response")) {

            AppLogger.warning(
                    "SBI discovery was cancelled or failed"
            );

            Toast.makeText(
                    this,
                    "Biometric device discovery was not completed.",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }

        byte[] response =
                data.getByteArrayExtra(
                        "response"
                );

        if (response == null
                || response.length == 0) {

            AppLogger.error(
                    "SBI discovery returned an empty response"
            );

            Toast.makeText(
                    this,
                    "No biometric device information was received.",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }

        String modality =
                discoveryTypes[discoveryIndex];

        try {

            DiscoverResponse sbi =
                    sbiService.parseDiscoveryResponse(
                            response,
                            modality
                    );

            if ("Finger".equals(modality)) {

                fingerSBI = sbi;

            } else if ("Face".equals(modality)) {

                faceSBI = sbi;

            } else if ("Iris".equals(modality)) {

                irisSBI = sbi;
            }

            AppLogger.success(
                    modality
                            + " biometric device saved"
            );

            discoveryIndex++;

            discoverNext();

        } catch (Exception e) {

            AppLogger.error(
                    "Unable to process "
                            + modality
                            + " discovery response"
            );

            Toast.makeText(
                    this,
                    "Unable to discover "
                            + modality
                            + " biometric device.",
                    Toast.LENGTH_LONG
            ).show();
        }
    }

    private void handleInfoResult(
            int resultCode,
            Intent data) {

        if (resultCode != RESULT_OK
                || data == null
                || !data.hasExtra("response")) {

            AppLogger.warning(
                    "SBI device information request was cancelled or failed"
            );

            Toast.makeText(
                    this,
                    "Unable to retrieve biometric device information.",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }

        byte[] response =
                data.getByteArrayExtra(
                        "response"
                );

        if (response == null
                || response.length == 0) {

            AppLogger.error(
                    "SBI device information response is empty"
            );

            Toast.makeText(
                    this,
                    "Biometric device information was not received.",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }

        try {

            DeviceInfoPayload info =
                    sbiService.parseDeviceInfoResponse(
                            response
                    );

            if (infoIndex == 0
                    && fingerSBI != null) {

                fingerInfo = info;

                AppLogger.success(
                        "Finger device information saved"
                );

            } else if (infoIndex == 1
                    && faceSBI != null) {

                faceInfo = info;

                AppLogger.success(
                        "Face device information saved"
                );

            } else if (infoIndex == 2
                    && irisSBI != null) {

                irisInfo = info;

                AppLogger.success(
                        "Iris device information saved"
                );

            } else {

                AppLogger.warning(
                        "Unable to associate device information with modality"
                );
            }

            infoIndex++;

            getNextDeviceInfo();

        } catch (Exception e) {

            AppLogger.error(
                    "Unable to process SBI device information"
            );

            Toast.makeText(
                    this,
                    "Unable to retrieve biometric device information.",
                    Toast.LENGTH_LONG
            ).show();
        }
    }

    private void handleCaptureResult(
            int resultCode,
            Intent data) {

        if (resultCode != RESULT_OK
                || data == null
                || !data.hasExtra("response")) {

            AppLogger.error(
                    "SBI capture failed or was cancelled"
            );

            Toast.makeText(
                    this,
                    "Biometric capture was not completed.",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }

        Uri uri =
                data.getParcelableExtra(
                        "response"
                );

        if (uri == null) {

            AppLogger.error(
                    "SBI capture response URI not found"
            );

            Toast.makeText(
                    this,
                    "Unable to receive biometric data.",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }

        if (captureIndex >= captureModalities.size()) {

            AppLogger.error(
                    "Invalid capture index: "
                            + captureIndex
            );

            Toast.makeText(
                    this,
                    "Unable to process biometric capture.",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }

        String modality =
                captureModalities.get(
                        captureIndex
                );

        AppLogger.step(
                "Processing "
                        + modality
                        + " capture response"
        );

        try {

            List<JsonNode> biometricObjects =
                    sbiService.readCaptureResponse(
                            uri
                    );

            if (biometricObjects.isEmpty()) {

                AppLogger.error(
                        modality
                                + " response contains no biometric data"
                );

                Toast.makeText(
                        this,
                        "Biometric capture did not return valid data.",
                        Toast.LENGTH_LONG
                ).show();

                return;
            }

            for (JsonNode biometric :
                    biometricObjects) {

                JsonNode error =
                        biometric.get("error");

                if (error != null) {

                    String errorCode =
                            error.path(
                                    "errorCode"
                            ).asText();

                    String errorInfo =
                            error.path(
                                    "errorInfo"
                            ).asText();

                    AppLogger.info(
                            modality
                                    + " SBI error code: "
                                    + errorCode
                    );

                    if (!"0".equals(errorCode)
                            && !"100".equals(errorCode)) {

                        AppLogger.error(
                                modality
                                        + " capture failed: "
                                        + errorInfo
                        );

                        Toast.makeText(
                                this,
                                "Biometric capture failed. Please try again.",
                                Toast.LENGTH_LONG
                        ).show();

                        return;
                    }
                }

                capturedBiometrics.add(
                        biometric
                );

                AppLogger.success(
                        modality
                                + " biometric captured successfully"
                );

                AppLogger.info(
                        "Total captured biometrics: "
                                + capturedBiometrics.size()
                );

                JsonNode hashNode =
                        biometric.get("hash");

                if (hashNode != null
                        && !hashNode.isNull()
                        && !hashNode.asText().isEmpty()) {

                    previousHash =
                            hashNode.asText();

                    AppLogger.info(
                            "Previous biometric hash updated"
                    );
                }
            }

            captureIndex++;

            AppLogger.success(
                    modality
                            + " capture completed"
            );

            captureNext();

        } catch (Exception e) {

            AppLogger.error(
                    "Unable to process "
                            + modality
                            + " capture response"
            );

            Toast.makeText(
                    this,
                    "Unable to process biometric capture. Please try again.",
                    Toast.LENGTH_LONG
            ).show();
        }
    }

    // ============================================================
    // RESET
    // ============================================================

    private void resetApplication() {

        AppLogger.section(
                "================================"
        );

        AppLogger.section(
                "RESET"
        );

        AppLogger.section(
                "================================"
        );


        // Clear SBI information
        fingerSBI = null;
        faceSBI = null;
        irisSBI = null;


        // Clear Info
        fingerInfo = null;
        faceInfo = null;
        irisInfo = null;


        // Clear indexes
        discoveryIndex = 0;
        infoIndex = 0;
        captureIndex = 0;

        // Clear capture queue
        captureModalities.clear();


        // Clear UI selections
        fingerCheckBox.setChecked(false);
        faceCheckBox.setChecked(false);
        irisCheckBox.setChecked(false);


        AppLogger.info(
                "All saved state cleared"
        );


        Toast.makeText(
                this,
                "Resetting...",
                Toast.LENGTH_SHORT
        ).show();


        // Start again
        startDiscoverySequence();
    }

    private void setupFingerCountSpinner() {

        List<String> fingerCounts =
                new ArrayList<>();

        for (int i = 1; i <= 10; i++) {
            fingerCounts.add(
                    String.valueOf(i)
            );
        }

        ArrayAdapter<String> adapter =
                new ArrayAdapter<>(
                        this,
                        android.R.layout.simple_spinner_item,
                        fingerCounts
                );

        adapter.setDropDownViewResource(
                android.R.layout.simple_spinner_dropdown_item
        );

        fingerCountSpinner.setAdapter(adapter);

        // Initially select 1
        fingerCountSpinner.setSelection(0);
    }

    private void setupIrisTypeSpinner() {

        List<String> irisTypes =
                new ArrayList<>();

        irisTypes.add("Left Iris");
        irisTypes.add("Right Iris");
        irisTypes.add("Both Iris");

        ArrayAdapter<String> adapter =
                new ArrayAdapter<>(
                        this,
                        android.R.layout.simple_spinner_item,
                        irisTypes
                );

        adapter.setDropDownViewResource(
                android.R.layout.simple_spinner_dropdown_item
        );

        irisTypeSpinner.setAdapter(adapter);

        // Initially select Both Iris
        irisTypeSpinner.setSelection(2);
    }

    private void requestOtp() {

        if (otpService == null) {

            Toast.makeText(
                    this,
                    "OTP service is not available.",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }

        requestOtpButton.setEnabled(false);

        AppLogger.section(
                "REQUESTING OTP"
        );

        otpService.requestOtp(
                new OtpService.OtpCallback() {

                    @Override
                    public void onOtpRequested() {

                        requestOtpButton.setEnabled(true);

                        otpEditText.setEnabled(true);

                        otpEditText.requestFocus();

                        Toast.makeText(
                                MainActivity.this,
                                "OTP sent to registered email",
                                Toast.LENGTH_LONG
                        ).show();
                    }

                    @Override
                    public void onOtpRequestFailed(
                            String message
                    ) {

                        requestOtpButton.setEnabled(true);

                        otpEditText.setEnabled(false);
                    }
                }
        );
    }

    private void startAuthentication() {

        new Thread(() -> {

            try {

                if (MosipConfig.TRANSACTION_ID == null
                        || MosipConfig.TRANSACTION_ID.trim().isEmpty()) {

                    throw new Exception(
                            "Authentication transaction ID is not available"
                    );
                }

                AppLogger.section("================================");
                AppLogger.section("STARTING MOSIP AUTHENTICATION");
                AppLogger.section("================================");

                // ----------------------------------------------------
                // 1. Determine authentication methods
                // ----------------------------------------------------

                boolean hasBiometrics =
                        combinedBiometrics != null
                                && !combinedBiometrics.trim().isEmpty();

                String otp = null;

                if (otpEditText != null) {

                    otp =
                            otpEditText
                                    .getText()
                                    .toString()
                                    .trim();
                }

                boolean hasOtp =
                        otp != null
                                && !otp.isEmpty();

                if (!hasBiometrics && !hasOtp) {

                    runOnUiThread(() ->
                            Toast.makeText(
                                    MainActivity.this,
                                    "Please capture biometrics or enter OTP.",
                                    Toast.LENGTH_LONG
                            ).show()
                    );

                    AppLogger.warning(
                            "No authentication method selected"
                    );

                    return;
                }

                AppLogger.info(
                        "Biometric authentication = "
                                + hasBiometrics
                );

                AppLogger.info(
                        "OTP authentication = "
                                + hasOtp
                );

                // ----------------------------------------------------
                // 2. Build identity request
                // ----------------------------------------------------

                String identityRequest =
                        authRequestBuilder.buildIdentityRequest(
                                hasBiometrics
                                        ? combinedBiometrics
                                        : null,
                                hasOtp
                                        ? otp
                                        : null
                        );

                AppLogger.info(
                        "Identity request created"
                );

                AppLogger.d(
                        "DEBUG: Identity request length = "
                                + identityRequest.length()
                );

                // ----------------------------------------------------
                // 3. Get MOSIP certificate
                // ----------------------------------------------------

                X509Certificate certificate =
                        certificateService.getMosipCertificate();

                AppLogger.info(
                        "MOSIP encryption certificate loaded"
                );

                // ----------------------------------------------------
                // 4. Encrypt identity request
                // ----------------------------------------------------

                MosipCryptoService.EncryptionResult encryptionResult =
                        mosipCryptoService.encryptIdentityRequest(
                                identityRequest,
                                certificate
                        );

                AppLogger.info(
                        "Identity request encrypted successfully"
                );

                // ----------------------------------------------------
                // 5. Build Auth request
                // ----------------------------------------------------

                String authRequestJson =
                        authRequestBuilder.buildAuthRequest(
                                encryptionResult,
                                MosipConfig.TRANSACTION_ID,
                                hasBiometrics,
                                hasOtp
                        );

                AppLogger.info(
                        "Auth request created"
                );

                AppLogger.d(
                        "DEBUG: Auth request contains transaction ID = "
                                + authRequestJson.contains(
                                MosipConfig.TRANSACTION_ID
                        )
                );

                AppLogger.d(
                        "DEBUG: Auth request length = "
                                + authRequestJson.length()
                );

                // ----------------------------------------------------
                // 6. Generate MOSIP Authorization token
                // ----------------------------------------------------

                String authorizationToken =
                        authManagerService.getAuthManagerToken();

                if (authorizationToken == null
                        || authorizationToken.trim().isEmpty()) {

                    throw new Exception(
                            "Authorization token was not received from MOSIP Auth Manager"
                    );
                }

                AppLogger.info(
                        "Authorization token received successfully"
                );

                // ----------------------------------------------------
                // 7. Sign Auth request
                // ----------------------------------------------------

                AppLogger.section("================================");
                AppLogger.section("SIGNING AUTH REQUEST");
                AppLogger.section("================================");

                String signature =
                        partnerSignatureService.sign(
                                authRequestJson
                        );

                if (signature == null
                        || signature.trim().isEmpty()) {

                    throw new Exception(
                            "Auth request signature was not generated"
                    );
                }

                AppLogger.info(
                        "Auth signature generated"
                );

                // ----------------------------------------------------
                // 8. Send Auth request
                // ----------------------------------------------------

                AppLogger.section("================================");
                AppLogger.section("SENDING MOSIP AUTH REQUEST");
                AppLogger.section("================================");

                AppLogger.d(
                        "DEBUG: Sending Auth request"
                );

                mosipAuthService.sendAuthRequest(
                        authRequestJson,
                        signature,
                        authorizationToken
                );

            } catch (Exception e) {

                AppLogger.error(
                        "Authentication failed"
                );

                runOnUiThread(() ->
                        Toast.makeText(
                                MainActivity.this,
                                "Authentication failed. Check logs.",
                                Toast.LENGTH_LONG
                        ).show()
                );
            }

        }).start();
    }
}
