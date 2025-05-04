package client;

public class ClientOptions {
    private String serverAddress;
    private int serverPort;
    private boolean enableLogging;
    private boolean useQuantumEncryption;

    public ClientOptions() {
        // Default options
        this.serverAddress = "localhost";
        this.serverPort = 9000;
        this.enableLogging = true;
        this.useQuantumEncryption = true; 
    }

    // Getters and Setters
    public String getServerAddress() {
        return serverAddress;
    }

    public void setServerAddress(String serverAddress) {
        this.serverAddress = serverAddress;
    }

    public int getServerPort() {
        return serverPort;
    }

    public void setServerPort(int serverPort) {
        this.serverPort = serverPort;
    }

    public boolean isEnableLogging() {
        return enableLogging;
    }

    public void setEnableLogging(boolean enableLogging) {
        this.enableLogging = enableLogging;
    }

    public boolean isUseQuantumEncryption() {
        return useQuantumEncryption;
    }

    public void setUseQuantumEncryption(boolean useQuantumEncryption) {
        this.useQuantumEncryption = useQuantumEncryption;
    }
}

