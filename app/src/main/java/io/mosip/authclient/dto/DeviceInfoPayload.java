package io.mosip.authclient.dto;

import java.util.List;

public class DeviceInfoPayload {

    private List<String> specVersion;
    private String env;
    private String digitalId;
    private String deviceId;
    private String deviceCode;
    private String purpose;
    private String serviceVersion;
    private String deviceStatus;
    private String firmware;
    private String certification;
    private List<String> deviceSubId;
    private String callbackId;

    public List<String> getSpecVersion() {
        return specVersion;
    }

    public void setSpecVersion(List<String> specVersion) {
        this.specVersion = specVersion;
    }

    public String getEnv() {
        return env;
    }

    public void setEnv(String env) {
        this.env = env;
    }

    public String getDigitalId() {
        return digitalId;
    }

    public void setDigitalId(String digitalId) {
        this.digitalId = digitalId;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }

    public String getDeviceCode() {
        return deviceCode;
    }

    public void setDeviceCode(String deviceCode) {
        this.deviceCode = deviceCode;
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

    public String getDeviceStatus() {
        return deviceStatus;
    }

    public void setDeviceStatus(String deviceStatus) {
        this.deviceStatus = deviceStatus;
    }

    public String getFirmware() {
        return firmware;
    }

    public void setFirmware(String firmware) {
        this.firmware = firmware;
    }

    public String getCertification() {
        return certification;
    }

    public void setCertification(String certification) {
        this.certification = certification;
    }

    public List<String> getDeviceSubId() {
        return deviceSubId;
    }

    public void setDeviceSubId(List<String> deviceSubId) {
        this.deviceSubId = deviceSubId;
    }

    public String getCallbackId() {
        return callbackId;
    }

    public void setCallbackId(String callbackId) {
        this.callbackId = callbackId;
    }
}