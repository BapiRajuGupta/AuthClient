package io.mosip.authclient.dto;

import java.util.List;

public class CaptureRequest {

    private String env;
    private String purpose;
    private String specVersion;
    private int timeout;
    private String captureTime;
    private String domainUri;
    private String transactionId;
    private List<CaptureDeviceDetail> bio;
    private Object customOpts;

    public String getEnv() {
        return env;
    }

    public void setEnv(String env) {
        this.env = env;
    }

    public String getPurpose() {
        return purpose;
    }

    public void setPurpose(String purpose) {
        this.purpose = purpose;
    }

    public String getSpecVersion() {
        return specVersion;
    }

    public void setSpecVersion(String specVersion) {
        this.specVersion = specVersion;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public String getCaptureTime() {
        return captureTime;
    }

    public void setCaptureTime(String captureTime) {
        this.captureTime = captureTime;
    }

    public String getDomainUri() {
        return domainUri;
    }

    public void setDomainUri(String domainUri) {
        this.domainUri = domainUri;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public List<CaptureDeviceDetail> getBio() {
        return bio;
    }

    public void setBio(List<CaptureDeviceDetail> bio) {
        this.bio = bio;
    }

    public Object getCustomOpts() {
        return customOpts;
    }

    public void setCustomOpts(Object customOpts) {
        this.customOpts = customOpts;
    }
}