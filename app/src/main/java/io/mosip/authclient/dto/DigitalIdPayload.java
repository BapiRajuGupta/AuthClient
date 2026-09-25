package io.mosip.authclient.dto;

public class DigitalIdPayload {

    private String serialNo;
    private String make;
    private String model;
    private String type;
    private String deviceSubType;
    private String deviceProviderId;
    private String deviceProvider;
    private String dateTime;

    public String getSerialNo() {
        return serialNo;
    }

    public void setSerialNo(String serialNo) {
        this.serialNo = serialNo;
    }

    public String getMake() {
        return make;
    }

    public void setMake(String make) {
        this.make = make;
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getDeviceSubType() {
        return deviceSubType;
    }

    public void setDeviceSubType(String deviceSubType) {
        this.deviceSubType = deviceSubType;
    }

    public String getDeviceProviderId() {
        return deviceProviderId;
    }

    public void setDeviceProviderId(String deviceProviderId) {
        this.deviceProviderId = deviceProviderId;
    }

    public String getDeviceProvider() {
        return deviceProvider;
    }

    public void setDeviceProvider(String deviceProvider) {
        this.deviceProvider = deviceProvider;
    }

    public String getDateTime() {
        return dateTime;
    }

    public void setDateTime(String dateTime) {
        this.dateTime = dateTime;
    }
}