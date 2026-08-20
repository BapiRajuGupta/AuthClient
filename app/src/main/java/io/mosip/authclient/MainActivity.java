package io.mosip.authclient;

import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.Spinner;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import io.mosip.authclient.dto.CaptureDeviceDetail;
import io.mosip.authclient.dto.CaptureRequest;
import io.mosip.authclient.dto.DeviceInfoPayload;
import io.mosip.authclient.dto.DeviceInfoResponse;
import io.mosip.authclient.dto.DigitalIdPayload;
import io.mosip.authclient.dto.DiscoverResponse;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "AuthClient";

    // ------------------------------------------------------------
    // SBI application
    // ------------------------------------------------------------

    private String sbiPackageName;
    private String sbiActivityName;


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


    // ------------------------------------------------------------
    // UI
    // ------------------------------------------------------------

    private CheckBox fingerCheckBox;
    private CheckBox faceCheckBox;
    private CheckBox irisCheckBox;

    private Button discoverButton;
    private Button infoButton;
    private Button captureButton;
    private Button resetButton;

    private Spinner fingerCountSpinner;
    private Spinner irisTypeSpinner;


    // Discovery order
    private final String[] discoveryTypes = {
            "Finger",
            "Face",
            "Iris"
    };


    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);

        EdgeToEdge.enable(this);

        setContentView(R.layout.activity_main);


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

        resetButton =
                findViewById(R.id.resetButton);

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

        Log.d(
                TAG,
                "================================"
        );

        Log.d(
                TAG,
                "Starting Discovery sequence"
        );

        Log.d(
                TAG,
                "================================"
        );

        discoveryIndex = 0;

        discoverNext();
    }


    private void discoverNext() {

        if (discoveryIndex >= discoveryTypes.length) {

            Log.d(
                    TAG,
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


    private void discoverSBI(
            String biometricType) {

        try {

            Intent intent =
                    new Intent();

            intent.setAction(
                    "io.sbi.device"
            );


            PackageManager packageManager =
                    getPackageManager();


            List<ResolveInfo> activities =
                    packageManager.queryIntentActivities(
                            intent,
                            PackageManager.MATCH_DEFAULT_ONLY
                    );


            if (activities.isEmpty()) {

                Log.d(
                        TAG,
                        "No SBI application found"
                );

                Toast.makeText(
                        this,
                        "No SBI application found",
                        Toast.LENGTH_LONG
                ).show();

                return;
            }


            ResolveInfo activity =
                    activities.get(0);


            sbiPackageName =
                    activity.activityInfo
                            .applicationInfo
                            .packageName;

            sbiActivityName =
                    activity.activityInfo.name;


            intent.setComponent(
                    new ComponentName(
                            sbiPackageName,
                            sbiActivityName
                    )
            );


            // ----------------------------------------------------
            // IMPORTANT:
            //
            // Android MockSBI does NOT accept:
            //
            // {"type":"Biometric device"}
            //
            // So we discover each modality separately.
            // ----------------------------------------------------

            String request =
                    "{\"type\":\""
                            + biometricType
                            + "\"}";


            Log.d(
                    TAG,
                    "Discovery type: "
                            + biometricType
            );

            Log.d(
                    TAG,
                    "Discovery request: "
                            + request
            );


            intent.putExtra(
                    "input",
                    request.getBytes(
                            StandardCharsets.UTF_8
                    )
            );


            startActivityForResult(
                    intent,
                    100
            );


        } catch (Exception e) {

            Log.e(
                    TAG,
                    "Discovery error: "
                            + biometricType,
                    e
            );

            Toast.makeText(
                    this,
                    "Discovery error: "
                            + biometricType,
                    Toast.LENGTH_LONG
            ).show();
        }
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


        Log.d(
                TAG,
                "================================"
        );

        Log.d(
                TAG,
                "Starting Info sequence"
        );

        Log.d(
                TAG,
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

            Log.d(
                    TAG,
                    "All Info requests completed"
            );

            Toast.makeText(
                    this,
                    "Discovery + Info completed",
                    Toast.LENGTH_LONG
            ).show();
        }
    }


    private void getDeviceInfo(
            DiscoverResponse sbi) {

        try {

            String action =
                    sbi.getCallbackId()
                            + ".Info";


            Log.d(
                    TAG,
                    "Info action: "
                            + action
            );


            Intent intent =
                    new Intent();

            intent.setAction(
                    action
            );


            intent.setComponent(
                    new ComponentName(
                            sbiPackageName,
                            sbiActivityName
                    )
            );


            Log.d(
                    TAG,
                    "Sending Info request"
            );


            startActivityForResult(
                    intent,
                    101
            );


        } catch (Exception e) {

            Log.e(
                    TAG,
                    "Info request failed",
                    e
            );

            Toast.makeText(
                    this,
                    "Info request failed",
                    Toast.LENGTH_LONG
            ).show();
        }
    }


    // ============================================================
    // CAPTURE
    // ============================================================

    private void startCapture() {

        captureModalities.clear();


        // --------------------------------------------------------
        // Determine selected modalities
        // --------------------------------------------------------

        if (fingerCheckBox.isChecked()) {

            captureModalities.add(
                    "Finger"
            );
        }


        if (faceCheckBox.isChecked()) {

            captureModalities.add(
                    "Face"
            );
        }


        if (irisCheckBox.isChecked()) {

            captureModalities.add(
                    "Iris"
            );
        }


        if (captureModalities.isEmpty()) {

            Toast.makeText(
                    this,
                    "Select at least one biometric",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }


        // --------------------------------------------------------
        // Make sure required Info is available
        // --------------------------------------------------------

        for (String modality
                : captureModalities) {

            if (modality.equals("Finger")
                    && fingerInfo == null) {

                Toast.makeText(
                        this,
                        "Finger Info not available",
                        Toast.LENGTH_LONG
                ).show();

                return;
            }


            if (modality.equals("Face")
                    && faceInfo == null) {

                Toast.makeText(
                        this,
                        "Face Info not available",
                        Toast.LENGTH_LONG
                ).show();

                return;
            }


            if (modality.equals("Iris")
                    && irisInfo == null) {

                Toast.makeText(
                        this,
                        "Iris Info not available",
                        Toast.LENGTH_LONG
                ).show();

                return;
            }
        }


        captureIndex = 0;


        Log.d(
                TAG,
                "Capture sequence:"
                        + " "
                        + captureModalities
        );


        captureNext();
    }


    private void captureNext() {

        if (captureIndex >=
                captureModalities.size()) {

            Log.d(
                    TAG,
                    "All selected captures completed"
            );

            Toast.makeText(
                    this,
                    "All captures completed",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }


        String modality =
                captureModalities.get(
                        captureIndex
                );


        Log.d(
                TAG,
                "Starting capture: "
                        + modality
        );


        captureForModality(
                modality
        );
    }


    private void captureForModality(
            String modality) {

        DiscoverResponse sbi;
        DeviceInfoPayload info;


        // --------------------------------------------------------
        // Select correct SBI + Info
        // --------------------------------------------------------

        if (modality.equals("Finger")) {

            sbi = fingerSBI;
            info = fingerInfo;

        } else if (modality.equals("Face")) {

            sbi = faceSBI;
            info = faceInfo;

        } else {

            sbi = irisSBI;
            info = irisInfo;
        }


        if (sbi == null
                || info == null) {

            Toast.makeText(
                    this,
                    modality
                            + " SBI/Info unavailable",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }


        try {

            String action =
                    sbi.getCallbackId()
                            + ".Capture";


            Log.d(
                    TAG,
                    "Capture action: "
                            + action
            );


            Intent intent =
                    new Intent();

            intent.setAction(
                    action
            );


            // ----------------------------------------------------
            // Capture Request
            // ----------------------------------------------------

            CaptureRequest request =
                    new CaptureRequest();


            request.setEnv(
                    info.getEnv()
            );


            request.setPurpose(
                    info.getPurpose()
            );


            request.setSpecVersion(
                    info.getSpecVersion()
                            .get(0)
            );


            request.setTimeout(
                    10000
            );


            /*
             * Temporary value.
             * We will replace this later with actual UTC time.
             */
            request.setCaptureTime(
                    "2026-08-19T10:00:00Z"
            );


            request.setDomainUri(
                    ""
            );


            request.setTransactionId(
                    String.valueOf(
                            System.currentTimeMillis()
                    )
            );


            // ----------------------------------------------------
            // Bio details
            // ----------------------------------------------------

            CaptureDeviceDetail bio =
                    new CaptureDeviceDetail();


            bio.setType(
                    modality
            );


            configureBiometricRequest(
                    bio,
                    modality
            );


            bio.setRequestedScore(
                    40
            );


            bio.setDeviceId(
                    info.getDeviceId()
            );


            bio.setDeviceSubId(
                    info.getDeviceSubId()
                            .get(0)
            );


            bio.setPreviousHash(
                    ""
            );


            List<CaptureDeviceDetail> bioList =
                    new ArrayList<>();

            bioList.add(
                    bio
            );


            request.setBio(
                    bioList
            );


            request.setCustomOpts(
                    null
            );


            // ----------------------------------------------------
            // Convert request to JSON
            // ----------------------------------------------------

            ObjectMapper objectMapper =
                    new ObjectMapper();


            byte[] input =
                    objectMapper.writeValueAsBytes(
                            request
                    );


            String requestJson =
                    new String(
                            input,
                            StandardCharsets.UTF_8
                    );


            Log.d(
                    TAG,
                    "--------------------------------"
            );

            Log.d(
                    TAG,
                    "Capture modality: "
                            + modality
            );

            Log.d(
                    TAG,
                    "Capture request: "
                            + requestJson
            );

            Log.d(
                    TAG,
                    "--------------------------------"
            );


            // ----------------------------------------------------
            // Send to SBI
            // ----------------------------------------------------

            intent.putExtra(
                    "input",
                    input
            );


            intent.setComponent(
                    new ComponentName(
                            sbiPackageName,
                            sbiActivityName
                    )
            );


            startActivityForResult(
                    intent,
                    102
            );


        } catch (Exception e) {

            Log.e(
                    TAG,
                    "Capture request failed: "
                            + modality,
                    e
            );

            Toast.makeText(
                    this,
                    "Capture request failed: "
                            + modality,
                    Toast.LENGTH_LONG
            ).show();
        }
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
        // DISCOVERY RESPONSE
        // ========================================================

        if (requestCode == 100) {

            if (resultCode == RESULT_OK
                    && data != null
                    && data.hasExtra("response")) {

                byte[] response =
                        data.getByteArrayExtra(
                                "response"
                        );


                String responseText =
                        new String(
                                response,
                                StandardCharsets.UTF_8
                        );


                Log.d(
                        TAG,
                        "Discovery response for "
                                + discoveryTypes[
                                discoveryIndex
                                ]
                                + ": "
                                + responseText
                );


                try {

                    ObjectMapper objectMapper =
                            new ObjectMapper();


                    List<DiscoverResponse> responses =
                            objectMapper.readValue(
                                    response,
                                    new TypeReference<
                                            List<DiscoverResponse>
                                            >() {}
                            );


                    if (responses.isEmpty()) {

                        Log.d(
                                TAG,
                                "No device found for "
                                        + discoveryTypes[
                                        discoveryIndex
                                        ]
                        );

                    } else {

                        /*
                         * For each discovery request we
                         * expect the corresponding modality.
                         *
                         * We take the first response.
                         */

                        DiscoverResponse sbi =
                                responses.get(0);


                        String modality =
                                discoveryTypes[
                                        discoveryIndex
                                        ];


                        // ----------------------------------------
                        // Save SBI
                        // ----------------------------------------

                        if (modality.equals("Finger")) {

                            fingerSBI = sbi;

                        } else if (
                                modality.equals("Face")) {

                            faceSBI = sbi;

                        } else if (
                                modality.equals("Iris")) {

                            irisSBI = sbi;
                        }


                        // ----------------------------------------
                        // Decode Discovery digitalId
                        // ----------------------------------------

                        DigitalIdPayload digitalId =
                                decodeDiscoveryDigitalId(
                                        sbi.getDigitalId()
                                );


                        /*
                         * Save decoded Digital ID
                         * inside the DiscoverResponse.
                         */
                        sbi.setDecodedDigitalId(
                                digitalId
                        );


                        Log.d(
                                TAG,
                                "Discovered "
                                        + modality
                        );

                        Log.d(
                                TAG,
                                "Device ID: "
                                        + sbi.getDeviceId()
                        );

                        Log.d(
                                TAG,
                                "Callback ID: "
                                        + sbi.getCallbackId()
                        );

                        Log.d(
                                TAG,
                                "Device Status: "
                                        + sbi.getDeviceStatus()
                        );

                        Log.d(
                                TAG,
                                "Digital ID Serial: "
                                        + digitalId
                                        .getSerialNo()
                        );

                        Log.d(
                                TAG,
                                "Digital ID Model: "
                                        + digitalId
                                        .getModel()
                        );

                        Log.d(
                                TAG,
                                "Digital ID Type: "
                                        + digitalId
                                        .getType()
                        );
                    }


                    // Move to next modality
                    discoveryIndex++;

                    discoverNext();


                } catch (Exception e) {

                    Log.e(
                            TAG,
                            "Unable to parse discovery response",
                            e
                    );

                    Toast.makeText(
                            this,
                            "Unable to parse "
                                    + discoveryTypes[
                                    discoveryIndex
                                    ]
                                    + " discovery",
                            Toast.LENGTH_LONG
                    ).show();
                }

            } else {

                Log.d(
                        TAG,
                        "Discovery cancelled/failed"
                );

                Toast.makeText(
                        this,
                        "Discovery failed",
                        Toast.LENGTH_LONG
                ).show();
            }

            return;
        }


        // ========================================================
        // INFO RESPONSE
        // ========================================================

        if (requestCode == 101) {

            if (resultCode == RESULT_OK
                    && data != null
                    && data.hasExtra("response")) {

                byte[] response =
                        data.getByteArrayExtra(
                                "response"
                        );


                String responseText =
                        new String(
                                response,
                                StandardCharsets.UTF_8
                        );


                Log.d(
                        TAG,
                        "Info response: "
                                + responseText
                );


                try {

                    ObjectMapper objectMapper =
                            new ObjectMapper();


                    List<DeviceInfoResponse> responses =
                            objectMapper.readValue(
                                    response,
                                    new TypeReference<
                                            List<DeviceInfoResponse>
                                            >() {}
                            );


                    if (responses.isEmpty()) {

                        throw new Exception(
                                "Empty Info response"
                        );
                    }


                    DeviceInfoResponse infoResponse =
                            responses.get(0);


                    // --------------------------------------------
                    // SBI error
                    // --------------------------------------------

                    if (infoResponse.getError() != null
                            && !"0".equals(
                            infoResponse
                                    .getError()
                                    .getErrorCode())) {

                        throw new Exception(
                                infoResponse
                                        .getError()
                                        .getErrorInfo()
                        );
                    }


                    // --------------------------------------------
                    // Decode deviceInfo JWT
                    // --------------------------------------------

                    byte[] payload =
                            getJwtPayload(
                                    infoResponse
                                            .getDeviceInfo()
                            );


                    if (payload == null) {

                        throw new Exception(
                                "Unable to decode deviceInfo JWT"
                        );
                    }


                    DeviceInfoPayload info =
                            objectMapper.readValue(
                                    payload,
                                    DeviceInfoPayload.class
                            );


                    /*
                     * IMPORTANT:
                     *
                     * We DO NOT decode digitalId here.
                     *
                     * digitalId was already obtained
                     * from Discovery.
                     */


                    // --------------------------------------------
                    // Save Info against correct modality
                    // --------------------------------------------

                    if (infoIndex == 0
                            && fingerSBI != null) {

                        fingerInfo = info;

                        Log.d(
                                TAG,
                                "Finger Info saved"
                        );

                    } else if (
                            infoIndex == 1
                                    && faceSBI != null) {

                        faceInfo = info;

                        Log.d(
                                TAG,
                                "Face Info saved"
                        );

                    } else if (
                            infoIndex == 2
                                    && irisSBI != null) {

                        irisInfo = info;

                        Log.d(
                                TAG,
                                "Iris Info saved"
                        );
                    }


                    Log.d(
                            TAG,
                            "Device ID: "
                                    + info.getDeviceId()
                    );

                    Log.d(
                            TAG,
                            "Device Status: "
                                    + info.getDeviceStatus()
                    );

                    Log.d(
                            TAG,
                            "Firmware: "
                                    + info.getFirmware()
                    );


                    // Move to next modality
                    infoIndex++;

                    getNextDeviceInfo();


                } catch (Exception e) {

                    Log.e(
                            TAG,
                            "Unable to parse info response",
                            e
                    );

                    Toast.makeText(
                            this,
                            "Unable to parse Info response",
                            Toast.LENGTH_LONG
                    ).show();
                }

            } else {

                Toast.makeText(
                        this,
                        "Info request failed",
                        Toast.LENGTH_LONG
                ).show();
            }

            return;
        }


        // ========================================================
        // CAPTURE RESPONSE
        // ========================================================

        if (requestCode == 102) {

            if (resultCode == RESULT_OK
                    && data != null
                    && data.hasExtra("response")) {

                Uri uri =
                        data.getParcelableExtra(
                                "response"
                        );


                if (uri == null) {

                    Toast.makeText(
                            this,
                            "Capture response URI not found",
                            Toast.LENGTH_LONG
                    ).show();

                    return;
                }


                Log.d(
                        TAG,
                        "Capture response URI: "
                                + uri
                );


                try {

                    InputStream inputStream =
                            getContentResolver()
                                    .openInputStream(
                                            uri
                                    );


                    byte[] response =
                            readBytes(
                                    inputStream
                            );


                    String responseText =
                            new String(
                                    response,
                                    StandardCharsets.UTF_8
                            );


                    Log.d(
                            TAG,
                            "Capture response: "
                                    + responseText
                    );


                    String modality =
                            captureModalities.get(
                                    captureIndex
                            );


                    Log.d(
                            TAG,
                            "Completed capture: "
                                    + modality
                    );


                    Toast.makeText(
                            this,
                            modality
                                    + " capture completed",
                            Toast.LENGTH_SHORT
                    ).show();


                    // Move to next selected modality
                    captureIndex++;

                    captureNext();


                } catch (Exception e) {

                    Log.e(
                            TAG,
                            "Unable to read capture response",
                            e
                    );

                    Toast.makeText(
                            this,
                            "Unable to read capture response",
                            Toast.LENGTH_LONG
                    ).show();
                }

            } else {

                Toast.makeText(
                        this,
                        "Capture failed",
                        Toast.LENGTH_LONG
                ).show();
            }
        }
    }


    // ============================================================
    // DISCOVERY DIGITAL ID DECODER
    // ============================================================

    private DigitalIdPayload
    decodeDiscoveryDigitalId(
            String digitalId)
            throws Exception {

        byte[] decoded =
                Base64.decode(
                        digitalId,
                        Base64.DEFAULT
                );


        ObjectMapper objectMapper =
                new ObjectMapper();


        return objectMapper.readValue(
                decoded,
                DigitalIdPayload.class
        );
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

            Log.e(
                    TAG,
                    "JWT decode failed",
                    e
            );

            return null;
        }
    }


    // ============================================================
    // READ CONTENT URI
    // ============================================================

    private byte[] readBytes(
            InputStream inputStream)
            throws Exception {

        java.io.ByteArrayOutputStream buffer =
                new java.io.ByteArrayOutputStream();


        byte[] data =
                new byte[4096];


        int bytesRead;


        while (
                (bytesRead =
                        inputStream.read(data))
                        != -1
        ) {

            buffer.write(
                    data,
                    0,
                    bytesRead
            );
        }


        inputStream.close();


        return buffer.toByteArray();
    }


    // ============================================================
    // RESET
    // ============================================================

    private void resetApplication() {

        Log.d(
                TAG,
                "================================"
        );

        Log.d(
                TAG,
                "RESET"
        );

        Log.d(
                TAG,
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


        Log.d(
                TAG,
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

    private void configureBiometricRequest(
            CaptureDeviceDetail bio,
            String modality) {

        // ------------------------------------------------------------
        // FINGER
        // ------------------------------------------------------------

        if (modality.equals("Finger")) {

            int count =
                    Integer.parseInt(
                            fingerCountSpinner
                                    .getSelectedItem()
                                    .toString()
                    );

            bio.setCount(
                    String.valueOf(count)
            );


            /*
             * For now we don't know the exact
             * fingers being captured.
             *
             * Therefore use UNKNOWN for every
             * requested biometric.
             *
             * Example count = 3:
             *
             * ["UNKNOWN", "UNKNOWN", "UNKNOWN"]
             */

            String[] subTypes =
                    new String[count];

            for (int i = 0; i < count; i++) {

                subTypes[i] =
                        "UNKNOWN";
            }

            bio.setBioSubType(
                    subTypes
            );
        }


        // ------------------------------------------------------------
        // IRIS
        // ------------------------------------------------------------

        else if (modality.equals("Iris")) {

            String selected =
                    irisTypeSpinner
                            .getSelectedItem()
                            .toString();


            if (selected.equals("Left Iris")) {

                bio.setCount("1");

                bio.setBioSubType(
                        new String[]{
                                "Left"
                        }
                );
            }


            else if (
                    selected.equals("Right Iris")) {

                bio.setCount("1");

                bio.setBioSubType(
                        new String[]{
                                "Right"
                        }
                );
            }


            else {

                /*
                 * Both Iris
                 */

                bio.setCount("2");

                bio.setBioSubType(
                        new String[]{
                                "Left",
                                "Right"
                        }
                );
            }
        }


        // ------------------------------------------------------------
        // FACE
        // ------------------------------------------------------------

        else if (modality.equals("Face")) {

            /*
             * Face is always count 1.
             *
             * MOSIP specification says Face has
             * no bioSubType.
             */

            bio.setCount("1");
        }
    }
}