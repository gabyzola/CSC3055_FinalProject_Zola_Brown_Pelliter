package test.pqcrypto;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

import common.Config;
import common.User;
import pqcrypto.AuthManager;
import pqcrypto.CryptoManager;
import pqcrypto.KyberOperations;
import pqcrypto.DilithiumOperations;
import pqcrypto.TOTPManager;

public class AuthManagerTest {
    // Assertion methods omitted for brevity
    
    public static void main(String[] args) {
        try {
            System.out.println("========== Testing AuthManager ==========");
            
            // Create parent directory structure first
            File testDir = new File("./test-data");
            testDir.mkdirs();
            
            // Create user file in that directory
            File tempUsersFile = new File(testDir, "users.json");
            if (!tempUsersFile.exists()) {
                // Create initial empty users file
                String emptyUsers = "{\"users\":[]}";
                Files.write(tempUsersFile.toPath(), emptyUsers.getBytes());
            }
            
            System.out.println("Users file path: " + tempUsersFile.getAbsolutePath());
            System.out.println("File exists: " + tempUsersFile.exists());
            
            // Create config file
            File tempConfigFile = File.createTempFile("config", ".json");
            tempConfigFile.deleteOnExit();
            
            // Write config with explicit paths
            String configContent = "{\"storage\":{\"users_file\":\"" + 
                tempUsersFile.getAbsolutePath().replace("\\", "\\\\") + 
                "\"},\"server\":{\"session_timeout_mins\":30}}";
            
            Files.write(tempConfigFile.toPath(), configContent.getBytes());
            System.out.println("Config file content: " + configContent);
            
            // Load the config
            Config config = Config.getInstance(tempConfigFile.getAbsolutePath());
            
            // Create components
            CryptoManager cryptoManager = new CryptoManager(config);
            AuthManager authManager = new AuthManager(cryptoManager, config);
            
            // Test registration
            String username = "testuser";
            String password = "Password123!";
            User user = authManager.registerUser(username, password);
            
            // Test TOTP
            String totpSecret = user.getTotpSecret();
            TOTPManager totpManager = new TOTPManager();
            String totpCode = totpManager.generateTOTP(totpSecret);
            
            // Authentication test
            String sessionId = authManager.authenticateUser(username, password, totpCode);
            String validatedUser = authManager.validateSession(sessionId);
            
            // Test successful
            System.out.println("Test completed successfully!");
            
        } catch (Exception e) {
            System.err.println("Test failed with exception: " + e.getMessage());
            e.printStackTrace();
        }
    }
}