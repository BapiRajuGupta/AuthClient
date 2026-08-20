package io.mosip.authclient.dto;

import java.util.List;

public class DiscoverResponse {

    private String callbackId;
    private String certification;
    private String deviceCode;
    private String deviceId;
    private String deviceStatus;
    private List<String> deviceSubId;
    private String digitalId;
    private ErrorResponse error;
    private String purpose;
    private String serviceVersion;
    private List<String> specVersion;

    private DigitalIdPayload decodedDigitalId;

    public String getCallbackId() {
        return callbackId;
    }

    public void setCallbackId(String callbackId) {
        this.callbackId = callbackId;
    }

    public String getCertification() {
        return certification;
    }

    public void setCertification(String certification) {
        this.certification = certification;
    }

    public String getDeviceCode() {
        return deviceCode;
    }

    public void setDeviceCode(String deviceCode) {
        this.deviceCode = deviceCode;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }

    public String getDeviceStatus() {
        return deviceStatus;
    }

    public void setDeviceStatus(String deviceStatus) {
        this.deviceStatus = deviceStatus;
    }

    public List<String> getDeviceSubId() {
        return deviceSubId;
    }

    public void setDeviceSubId(List<String> deviceSubId) {
        this.deviceSubId = deviceSubId;
    }

    public String getDigitalId() {
        return digitalId;
    }

    public void setDigitalId(String digitalId) {
        this.digitalId = digitalId;
    }

    public ErrorResponse getError() {
        return error;
    }

    public void setError(ErrorResponse error) {
        this.error = error;
    }

    public String getPurpose() {
        return purpose;
    }

    public void setPurpose(String purpose) {
        this.purpose = purpose;
    }

    public String getServiceVersion() {
        return serviceVersion;
    }

    public void setServiceVersion(String serviceVersion) {
        this.serviceVersion = serviceVersion;
    }

    public List<String> getSpecVersion() {
        return specVersion;
    }

    public void setSpecVersion(List<String> specVersion) {
        this.specVersion = specVersion;
    }

    public DigitalIdPayload getDecodedDigitalId() {
        return decodedDigitalId;
    }

    public void setDecodedDigitalId(
            DigitalIdPayload decodedDigitalId) {
        this.decodedDigitalId = decodedDigitalId;
    }
}