package client;

/**
 * Simple test class for ClientOptions
 */
public class ClientOptionsTest {
    
    public static void main(String[] args) {
        // Test various option combinations
        testRegistration();
        testUpload();
        testDownload();
        testList();
        testBlockchain();
        testInvalidOptions();
        
        System.out.println("All tests completed!");
    }
    
    private static void testRegistration() {
        System.out.println("\n=== Testing Registration ===");
        ClientOptions options = new ClientOptions();
        String[] registerArgs = {
            "--register",
            "--user", "testuser",
            "--host", "localhost",
            "--port", "5001"
        };
        
        boolean result = options.parseOptions(registerArgs);
        
        System.out.println("Parse successful: " + result);
        System.out.println("Is register: " + options.isRegister());
        System.out.println("Username: " + options.getUsername());
        System.out.println("Host: " + options.getHost());
        System.out.println("Port: " + options.getPort());
    }
    
    private static void testUpload() {
        System.out.println("\n=== Testing Upload ===");
        ClientOptions options = new ClientOptions();
        String[] uploadArgs = {
            "--upload", "test.txt",
            "--user", "testuser",
            "--host", "localhost",
            "--port", "5001"
        };
        
        boolean result = options.parseOptions(uploadArgs);
        
        System.out.println("Parse successful: " + result);
        System.out.println("Is upload: " + options.isUpload());
        System.out.println("File path: " + options.getFilePath());
        System.out.println("Username: " + options.getUsername());
    }
    
    private static void testDownload() {
        System.out.println("\n=== Testing Download ===");
        ClientOptions options = new ClientOptions();
        String[] downloadArgs = {
            "--download", "abc123hash",
            "--dest", "./downloads",
            "--user", "testuser",
            "--host", "localhost",
            "--port", "5001"
        };
        
        boolean result = options.parseOptions(downloadArgs);
        
        System.out.println("Parse successful: " + result);
        System.out.println("Is download: " + options.isDownload());
        System.out.println("File hash: " + options.getFileHash());
        System.out.println("Destination: " + options.getDestinationDir());
    }
    
    private static void testList() {
        System.out.println("\n=== Testing List ===");
        ClientOptions options = new ClientOptions();
        String[] listArgs = {
            "--list",
            "--user", "testuser",
            "--host", "localhost",
            "--port", "5001",
            "--user-only"
        };
        
        boolean result = options.parseOptions(listArgs);
        
        System.out.println("Parse successful: " + result);
        System.out.println("Is list: " + options.isList());
        System.out.println("User only: " + options.isUserOnly());
    }
    
    private static void testBlockchain() {
        System.out.println("\n=== Testing Blockchain ===");
        ClientOptions options = new ClientOptions();
        String[] blockchainArgs = {
            "--blockchain",
            "--user", "testuser",
            "--host", "localhost",
            "--port", "5001"
        };
        
        boolean result = options.parseOptions(blockchainArgs);
        
        System.out.println("Parse successful: " + result);
        System.out.println("Is blockchain: " + options.isBlockchain());
    }
    
    private static void testInvalidOptions() {
        System.out.println("\n=== Testing Invalid Options ===");
        ClientOptions options = new ClientOptions();
        String[] invalidArgs = {
            "--register",
            "--user", "testuser",
            "--host", "localhost",
            "--port", "invalid"
        };
        
        boolean result = options.parseOptions(invalidArgs);
        
        System.out.println("Parse successful: " + result);
        System.out.println("Result should be false for invalid port");
    }
}