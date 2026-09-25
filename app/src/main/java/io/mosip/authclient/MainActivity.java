package io.mosip.authclient;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
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

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import io.mosip.authclient.auth.AuthManagerService;
import io.mosip.authclient.auth.AuthRequestBuilder;
import io.mosip.authclient.auth.MosipAuthService;
import io.mosip.authclient.auth.OtpService;
import io.mosip.authclient.config.MosipConfig;
import io.mosip.authclient.config.SettingsStore;
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

    private static final int P12_FILE_REQUEST_CODE = 200;

    // ------------------------------------------------------------
    // UI
    // ------------------------------------------------------------

    private CheckBox fingerCheckBox;
    private CheckBox faceCheckBox;
    private CheckBox irisCheckBox;
    private CheckBox otpCheckBox;

    private Button discoverButton;
    private Button infoButton;
    private Button captureButton;
    private Button authButton;
    private Button requestOtpButton;
    private Button resetButton;

    private EditText otpEditText;
    private EditText individualIdEditText;
    private EditText individualIdTypeEditText;

    private View authenticationTab;
    private View settingsTab;

    private View authScrollView;
    private View settingsScrollView;

    private View fingerOptionsSection;
    private View irisOptionsSection;
    private View otpSection;

    private Spinner fingerCountSpinner;
    private Spinner irisTypeSpinner;

    // --------------------------------------------------------
    // Settings UI elements
    // --------------------------------------------------------

    private EditText baseUrlEditText;
    private EditText domainUriEditText;
    private Spinner environmentSpinner;

    private EditText authManagerUrlEditText;
    private EditText authManagerClientIdEditText;
    private EditText authManagerSecretEditText;
    private EditText authManagerAppIdEditText;
    private EditText certificateUrlEditText;

    private EditText mispLicenseKeyEditText;
    private EditText partnerIdEditText;
    private EditText partnerApiKeyEditText;

    private EditText p12FileEditText;
    private EditText p12PasswordEditText;
    private EditText p12AliasEditText;

    private Button browseP12Button;
    private Button settingsSaveButton;
    private Button settingsCancelButton;


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
    private android.os.CountDownTimer resendOtpTimer;
    private boolean resendOtpCountdownActive = false;

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
    private SettingsStore settingsStore;
    private SettingsStore.Settings currentSettings;

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
                        this,
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

        settingsStore = new SettingsStore(
                this,
                objectMapper
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

        otpCheckBox =
                findViewById(R.id.otpCheckBox);

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

        individualIdEditText =
                findViewById(R.id.individualIdEditText);

        individualIdTypeEditText =
                findViewById(R.id.individualIdTypeEditText);

        authenticationTab =
                findViewById(R.id.authenticationTab);

        settingsTab =
                findViewById(R.id.settingsTab);

        authScrollView =
                findViewById(R.id.authScrollView);

        settingsScrollView =
                findViewById(R.id.settingsScrollView);

        fingerOptionsSection =
                findViewById(R.id.fingerOptionsSection);

        irisOptionsSection =
                findViewById(R.id.irisOptionsSection);

        otpSection =
                findViewById(R.id.otpSection);

        // --------------------------------------------------------
        // Settings UI elements
        // --------------------------------------------------------

        baseUrlEditText =
                findViewById(R.id.baseUrlEditText);

        domainUriEditText =
                findViewById(R.id.domainUriEditText);

        environmentSpinner =
                findViewById(R.id.environmentSpinner);

        authManagerUrlEditText =
                findViewById(R.id.authManagerUrlEditText);

        authManagerClientIdEditText =
                findViewById(R.id.authManagerClientIdEditText);

        authManagerSecretEditText =
                findViewById(R.id.authManagerSecretEditText);

        authManagerAppIdEditText =
                findViewById(R.id.authManagerAppIdEditText);

        certificateUrlEditText =
                findViewById(R.id.certificateUrlEditText);

        mispLicenseKeyEditText =
                findViewById(R.id.mispLicenseKeyEditText);

        partnerIdEditText =
                findViewById(R.id.partnerIdEditText);

        partnerApiKeyEditText =
                findViewById(R.id.partnerApiKeyEditText);

        p12FileEditText =
                findViewById(R.id.p12FileEditText);

        p12PasswordEditText =
                findViewById(R.id.p12PasswordEditText);

        p12AliasEditText =
                findViewById(R.id.p12AliasEditText);

        browseP12Button =
                findViewById(R.id.browseP12Button);

        settingsSaveButton =
                findViewById(R.id.settingsSaveButton);

        settingsCancelButton =
                findViewById(R.id.settingsCancelButton);

        setupEnvironmentSpinner();
        loadSettingsIntoUi();

        setupFingerCountSpinner();
        setupIrisTypeSpinner();

        // --------------------------------------------------------
        // Initial authentication UI state
        // --------------------------------------------------------

        setSectionEnabled(
               fingerOptionsSection,
                        false
                );

        setSectionEnabled(
                        irisOptionsSection,
                        false
                );

        setSectionEnabled(
                        otpSection,
                        false
                );

        authButton.setEnabled(false);
        captureButton.setEnabled(false);

        // --------------------------------------------------------
        // Authentication method selection
        // --------------------------------------------------------

        fingerCheckBox.setOnCheckedChangeListener(
                (buttonView, isChecked) -> {

                    setSectionEnabled(
                            fingerOptionsSection,
                            isChecked
                    );

                    // Biometric selection changed.
                    // Previous capture is no longer valid.
                    combinedBiometrics = null;
                    capturedBiometrics.clear();
                    previousHash = "";

                    updateAuthenticationButtons();
                }
        );

        faceCheckBox.setOnCheckedChangeListener(
                (buttonView, isChecked) -> {

                    // Biometric selection changed.
                    // Previous capture is no longer valid.
                    combinedBiometrics = null;
                    capturedBiometrics.clear();
                    previousHash = "";

                    updateAuthenticationButtons();
                }
        );

        irisCheckBox.setOnCheckedChangeListener(
                (buttonView, isChecked) -> {

                    setSectionEnabled(
                            irisOptionsSection,
                            isChecked
                    );

                    // Biometric selection changed.
                    // Previous capture is no longer valid.
                    combinedBiometrics = null;
                    capturedBiometrics.clear();
                    previousHash = "";

                    updateAuthenticationButtons();
                }
        );

        otpCheckBox.setOnCheckedChangeListener(
                (buttonView, isChecked) -> {

                    if (isChecked) {

                        // Enable OTP section
                        otpSection.setEnabled(true);

                        // Enable its children
                        for (int i = 0;
                             i < ((android.view.ViewGroup) otpSection).getChildCount();
                             i++) {

                            ((android.view.ViewGroup) otpSection)
                                    .getChildAt(i)
                                    .setEnabled(true);
                        }

                        // OTP input must remain disabled
                        // until Request OTP succeeds.
                        otpEditText.setEnabled(false);

                    } else {

                        // Disable entire OTP section
                        setSectionEnabled(
                                otpSection,
                                false
                        );

                        otpEditText.setText("");
                        otpEditText.setEnabled(false);
                    }

                    updateAuthenticationButtons();
                }
        );

        otpEditText.addTextChangedListener(
                new TextWatcher() {

                    @Override
                    public void beforeTextChanged(
                            CharSequence s,
                            int start,
                            int count,
                            int after
                    ) {
                    }

                    @Override
                    public void onTextChanged(
                            CharSequence s,
                            int start,
                            int before,
                            int count
                    ) {

                        updateAuthenticationButtons();
                    }

                    @Override
                    public void afterTextChanged(
                            Editable s
                    ) {
                    }
                }
        );

        individualIdEditText.addTextChangedListener(
                new TextWatcher() {

                    @Override
                    public void beforeTextChanged(
                            CharSequence s,
                            int start,
                            int count,
                            int after) {
                    }

                    @Override
                    public void onTextChanged(
                            CharSequence s,
                            int start,
                            int before,
                            int count) {

                        updateAuthenticationButtons();
                    }

                    @Override
                    public void afterTextChanged(Editable s) {
                    }
                }
        );

        // --------------------------------------------------------
        // Top tabs
        // --------------------------------------------------------

        authenticationTab.setOnClickListener(
                view -> showAuthenticationPage()
        );

        settingsTab.setOnClickListener(
                view -> {

                    loadSettingsIntoUi();

                    showSettingsPage();
                }
        );

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

        // --------------------------------------------------------
        // Mapping Setting Save & Cancel buttons
        // --------------------------------------------------------

        settingsSaveButton.setOnClickListener(
                view -> saveSettings()
        );

        settingsCancelButton.setOnClickListener(
                view -> cancelSettings()
        );


        browseP12Button.setOnClickListener(
                view -> {

                    Intent intent =
                            new Intent(
                                    Intent.ACTION_OPEN_DOCUMENT
                            );

                    intent.addCategory(
                            Intent.CATEGORY_OPENABLE
                    );

                    intent.setType(
                            "application/x-pkcs12"
                    );

                    startActivityForResult(
                            intent,
                            P12_FILE_REQUEST_CODE
                    );
                }
        );

        // Start SBI discovery automatically
        startDiscoverySequence();
    }

    // ============================================================
// PAGE NAVIGATION
// ============================================================

    private void showAuthenticationPage() {

        authScrollView.setVisibility(
                View.VISIBLE
        );

        settingsScrollView.setVisibility(
                View.GONE
        );

        authenticationTab.setBackgroundColor(
                android.graphics.Color.rgb(
                        36,
                        81,
                        166
                )
        );

        authenticationTab.setForeground(
                null
        );

        settingsTab.setBackgroundColor(
                android.graphics.Color.WHITE
        );

        if (authenticationTab instanceof android.widget.TextView) {

            ((android.widget.TextView) authenticationTab)
                    .setTextColor(
                            android.graphics.Color.WHITE
                    );
        }

        if (settingsTab instanceof android.widget.TextView) {

            ((android.widget.TextView) settingsTab)
                    .setTextColor(
                            android.graphics.Color.rgb(
                                    34,
                                    34,
                                    34
                            )
                    );
        }
    }


    private void showSettingsPage() {

        authScrollView.setVisibility(
                View.GONE
        );

        settingsScrollView.setVisibility(
                View.VISIBLE
        );

        settingsTab.setBackgroundColor(
                android.graphics.Color.rgb(
                        36,
                        81,
                        166
                )
        );

        authenticationTab.setBackgroundColor(
                android.graphics.Color.WHITE
        );

        if (settingsTab instanceof android.widget.TextView) {

            ((android.widget.TextView) settingsTab)
                    .setTextColor(
                            android.graphics.Color.WHITE
                    );
        }

        if (authenticationTab instanceof android.widget.TextView) {

            ((android.widget.TextView) authenticationTab)
                    .setTextColor(
                            android.graphics.Color.rgb(
                                    34,
                                    34,
                                    34
                            )
                    );
        }
    }

    private void setSectionEnabled(
            View view,
            boolean enabled
    ) {

        view.setEnabled(enabled);

        if (view instanceof android.view.ViewGroup) {

            android.view.ViewGroup viewGroup =
                    (android.view.ViewGroup) view;

            for (int i = 0;
                 i < viewGroup.getChildCount();
                 i++) {

                setSectionEnabled(
                        viewGroup.getChildAt(i),
                        enabled
                );
            }
        }
    }

    private void updateAuthenticationButtons() {

        // ============================================================
        // BIOMETRIC SELECTION
        // ============================================================

        boolean fingerSelected =
                fingerCheckBox.isChecked();

        boolean faceSelected =
                faceCheckBox.isChecked();

        boolean irisSelected =
                irisCheckBox.isChecked();

        boolean biometricSelected =
                fingerSelected
                        || faceSelected
                        || irisSelected;


        // ============================================================
        // BIOMETRIC DEVICE READINESS
        // ============================================================

        boolean fingerReady =
                fingerSelected
                        && fingerSBI != null
                        && fingerInfo != null;

        boolean faceReady =
                faceSelected
                        && faceSBI != null
                        && faceInfo != null;

        boolean irisReady =
                irisSelected
                        && irisSBI != null
                        && irisInfo != null;

        boolean biometricReadyForCapture =
                fingerReady
                        || faceReady
                        || irisReady;


        // ============================================================
        // CAPTURE BUTTON
        // ============================================================

        captureButton.setEnabled(
                biometricSelected
                        && biometricReadyForCapture
        );


        // ============================================================
        // OTP
        // ============================================================

        boolean otpSelected =
                otpCheckBox.isChecked();

        boolean individualIdReady =
                individualIdEditText != null
                        && !individualIdEditText
                        .getText()
                        .toString()
                        .trim()
                        .isEmpty();


        // ============================================================
        // REQUEST OTP BUTTON
        // ============================================================

        requestOtpButton.setEnabled(
                otpSelected
                        && individualIdReady
                        && !resendOtpCountdownActive
        );


        // ============================================================
        // BIOMETRIC AUTHENTICATION READY
        // ============================================================

        boolean biometricAuthenticationReady =
                biometricSelected
                        && combinedBiometrics != null
                        && !combinedBiometrics
                        .trim()
                        .isEmpty();


        // ============================================================
        // OTP AUTHENTICATION READY
        // ============================================================

        boolean otpAuthenticationReady =
                otpSelected
                        && otpEditText != null
                        && otpEditText.isEnabled()
                        && !otpEditText
                        .getText()
                        .toString()
                        .trim()
                        .isEmpty();


        // ============================================================
        // AUTHENTICATE BUTTON
        // ============================================================

        authButton.setEnabled(
                individualIdReady
                        && (
                        biometricAuthenticationReady
                                || otpAuthenticationReady
                )
        );
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

        // Clear previous SBI discovery information
        // before performing a fresh discovery.
        fingerSBI = null;
        faceSBI = null;
        irisSBI = null;

        fingerInfo = null;
        faceInfo = null;
        irisInfo = null;

        fingerCheckBox.setEnabled(false);
        faceCheckBox.setEnabled(false);
        irisCheckBox.setEnabled(false);

        fingerCheckBox.setChecked(false);
        faceCheckBox.setChecked(false);
        irisCheckBox.setChecked(false);

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

            AppLogger.info(
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

    private boolean isDeviceReady(DiscoverResponse sbi) {

        if (sbi == null
                || sbi.getDeviceStatus() == null) {
            return false;
        }

        return "Ready".equalsIgnoreCase(
                sbi.getDeviceStatus().trim()
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

            if (isDeviceReady(fingerSBI)) {
                getDeviceInfo(fingerSBI);
            } else {
                infoIndex++;
                getNextDeviceInfo();
            }

            return;
        }


        if (infoIndex == 1
                && faceSBI != null) {

            if (isDeviceReady(faceSBI)) {
                getDeviceInfo(faceSBI);
            } else {
                infoIndex++;
                getNextDeviceInfo();
            }

            return;
        }


        if (infoIndex == 2
                && irisSBI != null) {

            if (isDeviceReady(irisSBI)) {
                getDeviceInfo(irisSBI);
            } else {
                infoIndex++;
                getNextDeviceInfo();
            }

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

            AppLogger.info(
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

                AppLogger.warning(
                        "Failed to combine biometric responses"
                );

                Toast.makeText(
                        this,
                        "Unable to process biometric data. Please try again.",
                        Toast.LENGTH_LONG
                ).show();

                return;
            }

            // Update button state immediately after biometric capture is completed.
            updateAuthenticationButtons();

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
                    "Unable to create biometric request",
                    e
            );

            return null;
        }
    }

    private void captureForModality(
            String modality) {

        if (sbiService == null) {

            AppLogger.info(
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

            AppLogger.info(
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

    private void clearCaptureState() {

        captureIndex = 0;
        captureModalities.clear();

        capturedBiometrics.clear();
        combinedBiometrics = null;
        previousHash = "";

        updateAuthenticationButtons();

        AppLogger.info(
                "Biometric capture state cleared"
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

        // ========================================================
// P12 FILE SELECTION
// ========================================================

        if (requestCode == P12_FILE_REQUEST_CODE) {

            if (resultCode == RESULT_OK
                    && data != null
                    && data.getData() != null) {

                Uri uri =
                        data.getData();

                try {

                    String fileName =
                            "partner.p12";

                    java.io.File p12Directory =
                            new java.io.File(
                                    getFilesDir(),
                                    "certificates"
                            );

                    if (!p12Directory.exists()) {

                        if (!p12Directory.mkdirs()) {

                            throw new Exception(
                                    "Unable to create P12 directory"
                            );
                        }
                    }

                    java.io.File destinationFile =
                            new java.io.File(
                                    p12Directory,
                                    fileName
                            );

                    try (
                            InputStream inputStream =
                                    getContentResolver()
                                            .openInputStream(uri);

                            java.io.FileOutputStream outputStream =
                                    new java.io.FileOutputStream(
                                            destinationFile
                                    )
                    ) {

                        if (inputStream == null) {

                            throw new Exception(
                                    "Unable to open selected P12 file"
                            );
                        }

                        byte[] buffer =
                                new byte[8192];

                        int length;

                        while ((length =
                                inputStream.read(buffer)) != -1) {

                            outputStream.write(
                                    buffer,
                                    0,
                                    length
                            );
                        }

                        outputStream.flush();
                    }

                    p12FileEditText.setText(
                            destinationFile.getAbsolutePath()
                    );

                    Toast.makeText(
                            this,
                            "P12 file selected successfully",
                            Toast.LENGTH_SHORT
                    ).show();

                } catch (Exception e) {

                    AppLogger.error(
                            "Unable to copy P12 file",
                            e
                    );

                    Toast.makeText(
                            this,
                            "Unable to load P12 file",
                            Toast.LENGTH_LONG
                    ).show();
                }
            }

            return;
        }

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

            String modality =
                    discoveryTypes[discoveryIndex];

            AppLogger.warning(
                    modality + " SBI discovery was cancelled or failed"
            );

            Toast.makeText(
                    this,
                    modality + " biometric device was not discovered.",
                    Toast.LENGTH_SHORT
            ).show();

            // Continue with the next biometric modality.
            discoveryIndex++;
            discoverNext();

            return;
        }

        byte[] response =
                data.getByteArrayExtra(
                        "response"
                );

        if (response == null
                || response.length == 0) {

            String modality =
                    discoveryTypes[discoveryIndex];

            AppLogger.warning(
                    modality + " SBI discovery returned an empty response"
            );

            Toast.makeText(
                    this,
                    modality + " biometric device was not discovered.",
                    Toast.LENGTH_SHORT
            ).show();

            // Continue with the next biometric modality.
            discoveryIndex++;
            discoverNext();

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

            // Update checkbox based on device status.
            updateBiometricAvailability(
                    modality,
                    sbi
            );

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
                            + " discovery response",
                    e
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

    private String getInfoModality() {

        if (infoIndex == 0) {
            return "Finger";
        }

        if (infoIndex == 1) {
            return "Face";
        }

        if (infoIndex == 2) {
            return "Iris";
        }

        return "Biometric";
    }

    private void handleInfoResult(
            int resultCode,
            Intent data) {

        if (resultCode != RESULT_OK
                || data == null
                || !data.hasExtra("response")) {

            String modality = getInfoModality();

            AppLogger.warning(
                    modality + " SBI device information request failed"
            );

            Toast.makeText(
                    this,
                    modality + " biometric device information unavailable.",
                    Toast.LENGTH_SHORT
            ).show();

            // Continue with the next available device.
            infoIndex++;
            getNextDeviceInfo();

            return;
        }

        byte[] response =
                data.getByteArrayExtra(
                        "response"
                );

        if (response == null
                || response.length == 0) {

            String modality = getInfoModality();

            AppLogger.warning(
                    modality + " SBI device information response is empty"
            );

            Toast.makeText(
                    this,
                    modality + " biometric device information unavailable.",
                    Toast.LENGTH_SHORT
            ).show();

            infoIndex++;
            getNextDeviceInfo();

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
                    "Unable to process SBI device information",
                    e
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

            AppLogger.warning(
                    "SBI capture failed or was cancelled"
            );

            clearCaptureState();

            Toast.makeText(
                    this,
                    "Biometric capture was not completed. Please try again.",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }

        Uri uri =
                data.getParcelableExtra(
                        "response"
                );

        if (uri == null) {

            AppLogger.warning(
                    "SBI capture response URI not found"
            );

            clearCaptureState();

            Toast.makeText(
                    this,
                    "Unable to receive biometric data. Please try again.",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }

        if (captureIndex >= captureModalities.size()) {

            AppLogger.info(
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

                AppLogger.info(
                        modality
                                + " response contains no biometric data"
                );

                clearCaptureState();

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

                        AppLogger.info(
                                modality
                                        + " capture failed: "
                                        + errorInfo
                        );

                        clearCaptureState();

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

            AppLogger.info(
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

        // --------------------------------------------------------
        // Do NOT clear SBI discovery / device info
        //
        // These remain available after Reset.
        //
        // fingerSBI
        // faceSBI
        // irisSBI
        // fingerInfo
        // faceInfo
        // irisInfo
        // --------------------------------------------------------

        // Clear capture indexes/state
        captureIndex = 0;
        captureModalities.clear();

        // Clear authentication method selections
        fingerCheckBox.setChecked(false);
        faceCheckBox.setChecked(false);
        irisCheckBox.setChecked(false);
        otpCheckBox.setChecked(false);

        setSectionEnabled(
                otpSection,
                false
        );

        // Clear OTP
        otpEditText.setText("");
        otpEditText.setEnabled(false);

        // Clear temporary identity information
        individualIdEditText.setText("");
        individualIdTypeEditText.setText("UIN");

        // Clear captured biometric data
        combinedBiometrics = null;
        capturedBiometrics.clear();
        previousHash = "";

        // Reset authentication button states
        captureButton.setEnabled(false);
        authButton.setEnabled(false);

        // Stop OTP resend countdown
        if (resendOtpTimer != null) {
            resendOtpTimer.cancel();
            resendOtpTimer = null;
        }

        resendOtpCountdownActive = false;

        // Reset OTP request button
        requestOtpButton.setText("Request OTP");
        requestOtpButton.setEnabled(false);

        AppLogger.info(
                "Authentication state cleared. SBI discovery information retained."
        );

        Toast.makeText(
                this,
                "Authentication state reset",
                Toast.LENGTH_SHORT
        ).show();
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

        String individualId =
                individualIdEditText.getText()
                        .toString()
                        .trim();

        String individualIdType =
                individualIdTypeEditText.getText()
                        .toString()
                        .trim();

        if (individualId.isEmpty()) {
            Toast.makeText(
                    this,
                    "Please enter UIN.",
                    Toast.LENGTH_LONG
            ).show();
            return;
        }

        if (individualIdType.isEmpty()) {
            Toast.makeText(
                    this,
                    "Please enter UIN type.",
                    Toast.LENGTH_LONG
            ).show();
            return;
        }

        requestOtpButton.setEnabled(false);

        AppLogger.section(
                "REQUESTING OTP"
        );

        otpService.requestOtp(
                individualId,
                individualIdType,
                new OtpService.OtpCallback() {

                    @Override
                    public void onOtpRequested() {

                        otpEditText.setEnabled(true);

                        otpEditText.requestFocus();

                        startResendOtpCountdown();

                        updateAuthenticationButtons();

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

                        otpEditText.setEnabled(false);

                        updateAuthenticationButtons();
                    }
                }
        );
    }

    private void startResendOtpCountdown() {

        if (resendOtpTimer != null) {
            resendOtpTimer.cancel();
        }

        resendOtpCountdownActive = true;

        requestOtpButton.setEnabled(false);

        resendOtpTimer = new android.os.CountDownTimer(
                30000,
                1000
        ) {

            @Override
            public void onTick(long millisUntilFinished) {

                long secondsRemaining =
                        (millisUntilFinished + 999) / 1000;

                requestOtpButton.setText(
                        "Resend OTP (" + secondsRemaining + "s)"
                );
            }

            @Override
            public void onFinish() {

                resendOtpCountdownActive = false;

                requestOtpButton.setEnabled(
                        otpCheckBox.isChecked()
                                && !individualIdEditText
                                .getText()
                                .toString()
                                .trim()
                                .isEmpty()
                );

                requestOtpButton.setText(
                        "Resend OTP"
                );

                resendOtpTimer = null;

                updateAuthenticationButtons();
            }
        };

        resendOtpTimer.start();
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

                String individualId =
                        individualIdEditText
                                .getText()
                                .toString()
                                .trim();

                String individualIdType =
                        individualIdTypeEditText
                                .getText()
                                .toString()
                                .trim();

                if (individualId.isEmpty()) {

                    runOnUiThread(() ->
                            Toast.makeText(
                                    MainActivity.this,
                                    "Please enter UIN.",
                                    Toast.LENGTH_LONG
                            ).show()
                    );

                    return;
                }

                if (individualIdType.isEmpty()) {

                    runOnUiThread(() ->
                            Toast.makeText(
                                    MainActivity.this,
                                    "Please enter UIN type.",
                                    Toast.LENGTH_LONG
                            ).show()
                    );

                    return;
                }

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
                                hasOtp,
                                individualId,
                                individualIdType
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
                        authorizationToken,
                        new MosipAuthService.AuthCallback() {

                            @Override
                            public void onAuthenticationSuccess(
                                    String message
                            ) {

                                runOnUiThread(() ->
                                        Toast.makeText(
                                                MainActivity.this,
                                                message,
                                                Toast.LENGTH_LONG
                                        ).show()
                                );
                            }

                            @Override
                            public void onAuthenticationFailed(
                                    String message
                            ) {

                                runOnUiThread(() ->
                                        Toast.makeText(
                                                MainActivity.this,
                                                message,
                                                Toast.LENGTH_LONG
                                        ).show()
                                );
                            }

                            @Override
                            public void onAuthenticationError(
                                    String message
                            ) {

                                runOnUiThread(() ->
                                        Toast.makeText(
                                                MainActivity.this,
                                                message,
                                                Toast.LENGTH_LONG
                                        ).show()
                                );
                            }
                        }
                );

            } catch (Exception e) {

                AppLogger.error(
                        "Authentication failed",
                        e
                );

                runOnUiThread(() ->
                        Toast.makeText(
                                MainActivity.this,
                                "Authentication could not be completed. Please try again.",
                                Toast.LENGTH_LONG
                        ).show()
                );
            }

        }).start();
    }

    private void setupEnvironmentSpinner() {

        String[] environments = {
                "Production",
                "Staging"
        };

        ArrayAdapter<String> adapter =
                new ArrayAdapter<>(
                        this,
                        android.R.layout.simple_spinner_item,
                        environments
                );

        adapter.setDropDownViewResource(
                android.R.layout.simple_spinner_dropdown_item
        );

        environmentSpinner.setAdapter(adapter);
    }

    private void loadSettingsIntoUi() {

        try {

            currentSettings =
                    settingsStore.load();

            baseUrlEditText.setText(
                    currentSettings.baseUrl
            );

            domainUriEditText.setText(
                    currentSettings.domainUri
            );

            authManagerUrlEditText.setText(
                    currentSettings.authManagerUrl
            );

            authManagerClientIdEditText.setText(
                    currentSettings.authManagerClientId
            );

            authManagerSecretEditText.setText(
                    currentSettings.authManagerSecret
            );

            authManagerAppIdEditText.setText(
                    currentSettings.authManagerAppId
            );

            certificateUrlEditText.setText(
                    currentSettings.certificateUrl
            );

            mispLicenseKeyEditText.setText(
                    currentSettings.mispLicenseKey
            );

            partnerIdEditText.setText(
                    currentSettings.partnerId
            );

            partnerApiKeyEditText.setText(
                    currentSettings.partnerApiKey
            );

            p12FileEditText.setText(
                    currentSettings.p12Path
            );

            p12PasswordEditText.setText(
                    currentSettings.p12Password
            );

            p12AliasEditText.setText(
                    currentSettings.p12Alias
            );

            setEnvironmentSpinnerValue(
                    currentSettings.environment
            );

            AppLogger.info(
                    "Settings loaded"
            );

        } catch (Exception e) {

            AppLogger.error(
                    "Unable to load settings",
                    e
            );

            Toast.makeText(
                    this,
                    "Unable to load settings",
                    Toast.LENGTH_LONG
            ).show();
        }
    }

    private void setEnvironmentSpinnerValue(
            String environment
    ) {

        if (environment == null) {
            return;
        }

        ArrayAdapter adapter =
                (ArrayAdapter)
                        environmentSpinner.getAdapter();

        int position =
                adapter.getPosition(
                        environment
                );

        if (position >= 0) {

            environmentSpinner.setSelection(
                    position
            );
        }
    }

    private void saveSettings() {

        try {

            SettingsStore.Settings settings =
                    new SettingsStore.Settings();

            settings.baseUrl =
                    baseUrlEditText
                            .getText()
                            .toString()
                            .trim();

            settings.environment =
                    environmentSpinner
                            .getSelectedItem()
                            .toString();

            settings.domainUri =
                    domainUriEditText
                            .getText()
                            .toString()
                            .trim();

            settings.authManagerUrl =
                    authManagerUrlEditText
                            .getText()
                            .toString()
                            .trim();

            settings.authManagerClientId =
                    authManagerClientIdEditText
                            .getText()
                            .toString()
                            .trim();

            settings.authManagerSecret =
                    authManagerSecretEditText
                            .getText()
                            .toString();

            settings.authManagerAppId =
                    authManagerAppIdEditText
                            .getText()
                            .toString()
                            .trim();

            settings.certificateUrl =
                    certificateUrlEditText
                            .getText()
                            .toString()
                            .trim();

            settings.mispLicenseKey =
                    mispLicenseKeyEditText
                            .getText()
                            .toString()
                            .trim();

            settings.partnerId =
                    partnerIdEditText
                            .getText()
                            .toString()
                            .trim();

            settings.partnerApiKey =
                    partnerApiKeyEditText
                            .getText()
                            .toString()
                            .trim();

            settings.p12Path =
                    p12FileEditText
                            .getText()
                            .toString()
                            .trim();

            settings.p12Password =
                    p12PasswordEditText
                            .getText()
                            .toString();

            settings.p12Alias =
                    p12AliasEditText
                            .getText()
                            .toString()
                            .trim();

            settingsStore.save(
                    settings
            );

            currentSettings =
                    settings;

            Toast.makeText(
                    this,
                    "Settings saved",
                    Toast.LENGTH_SHORT
            ).show();

            AppLogger.success(
                    "Settings saved successfully"
            );

            showAuthenticationPage();

        } catch (Exception e) {

            AppLogger.error(
                    "Unable to save settings",
                    e
            );

            Toast.makeText(
                    this,
                    "Unable to save settings",
                    Toast.LENGTH_LONG
            ).show();
        }
    }

    private void cancelSettings() {

        loadSettingsIntoUi();

        showAuthenticationPage();

        Toast.makeText(
                this,
                "Changes cancelled",
                Toast.LENGTH_SHORT
        ).show();
    }

    private void updateBiometricAvailability(
            String modality,
            DiscoverResponse sbi) {

        boolean ready = isDeviceReady(sbi);

        if ("Finger".equals(modality)) {

            fingerCheckBox.setEnabled(ready);

            if (!ready) {
                fingerCheckBox.setChecked(false);
            }

        } else if ("Face".equals(modality)) {

            faceCheckBox.setEnabled(ready);

            if (!ready) {
                faceCheckBox.setChecked(false);
            }

        } else if ("Iris".equals(modality)) {

            irisCheckBox.setEnabled(ready);

            if (!ready) {
                irisCheckBox.setChecked(false);
            }
        }

        if (ready) {

            AppLogger.success(
                    modality + " biometric device is Ready"
            );

        } else {

            String status =
                    sbi != null && sbi.getDeviceStatus() != null
                            ? sbi.getDeviceStatus()
                            : "Unknown";

            AppLogger.warning(
                    modality
                            + " biometric device is not Ready. Status: "
                            + status
            );

            Toast.makeText(
                    this,
                    modality
                            + " device is "
                            + status
                            + ". It cannot be used.",
                    Toast.LENGTH_SHORT
            ).show();
        }

        updateAuthenticationButtons();
    }
}
