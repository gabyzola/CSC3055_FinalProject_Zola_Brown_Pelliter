package test;

import java.io.File;
import java.nio.file.Files;
import java.util.Random;

import client.Client;
import client.ClientOptions;
import client.CryptoManager;
import client.FileOperations;
import client.NetworkManager;
import common.Config;
import pqcrypto.FileServer;

/**
 * End-to-end test for the PQ Blockchain File Sharing system
 */
public class SystemTest {
    
    public static void main(String[] args) {
        try {
            // Start server in a separate thread
            Thread serverThread = new Thread(() -> {
                try {
                    FileServer server = new FileServer(null);
                    server.start();
                    
                    // Keep server running for test duration
                    Thread.sleep(30000);
                    server.stop();
                } catch (Exception e) {
                    System.err.println("Server error: " + e.getMessage());
                    e.printStackTrace();
                }
            });
            serverThread.start();
            
            // Wait for server to start
            Thread.sleep(2000);
            
            // Create test file
            File testFile = createTestFile();
            
            // Run registration process
            String[] registerArgs = {
                "--register",
                "--user", "testuser",
                "--host", "localhost",
                "--port", "5100"
            };
            runClient(registerArgs);
            
            // Run upload process
            String[] uploadArgs = {
                "--upload", testFile.getAbsolutePath(),
                "--user", "testuser",
                "--host", "localhost",
                "--port", "5100"
            };
            runClient(uploadArgs);
            
            // Run list process
            String[] listArgs = {
                "--list",
                "--user", "testuser",
                "--host", "localhost",
                "--port", "5100"
            };
            runClient(listArgs);
            
            // Clean up
            testFile.delete();
            System.out.println("Test completed successfully!");
            
        } catch (Exception e) {
            System.err.println("Test failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static void runClient(String[] args) throws Exception {
        Client client = new Client(args);
        client.run();
    }
    
    private static File createTestFile() throws Exception {
        // Create a random test file
        File testFile = new File("test_upload.txt");
        byte[] data = new byte[1024]; // 1KB test file
        new Random().nextBytes(data);
        Files.write(testFile.toPath(), data);
        return testFile;
    }
}