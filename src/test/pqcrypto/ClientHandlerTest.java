package test.pqcrypto;

import java.io.File;
import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.file.Files;

import blockchain.BlockchainManager;
import common.Config;
import common.Constants;
import common.JsonParser;
import common.Message;
import pqcrypto.AuthManager;
import pqcrypto.ClientHandler;
import pqcrypto.CryptoManager;
import pqcrypto.FileManager;
import pqcrypto.KyberOperations;

public class ClientHandlerTest {
    // Assertion methods omitted for brevity
    
    public static void main(String[] args) {
        try {
            System.out.println("========== Testing ClientHandler (Basic) ==========");
            
            // Create test directory structure
            File testDir = new File("./test-data/handler-test");
            testDir.mkdirs();
            
            File tempFileDir = new File(testDir, "files");
            tempFileDir.mkdirs();
            
            // Create blockchain file
            File tempBlockchainFile = new File(testDir, "blockchain.json");
            if (!tempBlockchainFile.exists()) {
                String emptyBlockchain = "{\"blockchain\":[{\"index\":0,\"timestamp\":\"2025-04-01T08:00:00Z\",\"previousHash\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"hash\":\"1a2b3c\",\"transactions\":[]}]}";
                Files.write(tempBlockchainFile.toPath(), emptyBlockchain.getBytes());
            }
            
            // Create users file
            File tempUsersFile = new File(testDir, "users.json");
            if (!tempUsersFile.exists()) {
                String emptyUsers = "{\"users\":[]}";
                Files.write(tempUsersFile.toPath(), emptyUsers.getBytes());
            }
            
            System.out.println("Test directory paths:");
            System.out.println("- Files: " + tempFileDir.getAbsolutePath());
            System.out.println("- Blockchain: " + tempBlockchainFile.getAbsolutePath());
            System.out.println("- Users: " + tempUsersFile.getAbsolutePath());
            
            // Create config file
            File configFile = File.createTempFile("handler-config", ".json");
            configFile.deleteOnExit();
            
            String configContent = "{" +
                "\"storage\": {" +
                    "\"file_storage_directory\": \"" + tempFileDir.getAbsolutePath().replace("\\", "\\\\") + "\"," +
                    "\"blockchain_file\": \"" + tempBlockchainFile.getAbsolutePath().replace("\\", "\\\\") + "\"," +
                    "\"users_file\": \"" + tempUsersFile.getAbsolutePath().replace("\\", "\\\\") + "\"" +
                "}," +
                "\"server\": {" +
                    "\"session_timeout_mins\": 30" +
                "}" +
            "}";
            
            Files.write(configFile.toPath(), configContent.getBytes());
            System.out.println("Config file: " + configFile.getAbsolutePath());
            
            // Load config
            Config config = Config.getInstance(configFile.getAbsolutePath());
            
            // Initialize components
            CryptoManager cryptoManager = new CryptoManager(config);
            BlockchainManager blockchainManager = new BlockchainManager(config);
            AuthManager authManager = new AuthManager(cryptoManager, config);
            FileManager fileManager = new FileManager(config, cryptoManager, blockchainManager);
            
            // Create mock socket and streams
            PipedOutputStream clientToServer = new PipedOutputStream();
            PipedInputStream serverFromClient = new PipedInputStream(clientToServer);
            
            PipedOutputStream serverToClient = new PipedOutputStream();
            PipedInputStream clientFromServer = new PipedInputStream(serverToClient);
            
            MockSocket mockSocket = new MockSocket(serverFromClient, serverToClient);
            
            // Create client handler
            ClientHandler clientHandler = new ClientHandler(
                mockSocket,
                cryptoManager,
                authManager,
                fileManager,
                blockchainManager
            );
            
            System.out.println("Created ClientHandler successfully");
            
            // Run a simple test with HELLO message
            Thread handlerThread = new Thread(clientHandler);
            handlerThread.start();
            System.out.println("Started ClientHandler thread");
            
            // Create client writer
            PrintWriter clientWriter = new PrintWriter(clientToServer, true);
            
            // Create Kyber keys for test
            KyberOperations kyber = new KyberOperations();
            //KyberOperations.KeyPair clientKeys = kyber.generateKeyPair();
            
            //Create and send HELLO message
            Message helloMessage = new Message(Constants.MSG_TYPE_HELLO);
            helloMessage.setPayload("clientId", "test-client");
            
            //String helloJson = helloMessage.serialize();
            // Use wrapper to serialize
            String helloJson = JsonParser.serializeMessage(helloMessage);
            System.out.println("Sending simple HELLO message: " + helloJson);
            clientWriter.println(helloJson);
            Thread.sleep(1000);

            System.out.println("SENING HELLO------");

            // String simpleJson = "{\"type\":\"HELLO\",\"version\":\"1.0\",\"nonce\":\"abcdef\",\"headers\":{},\"payload\":{\"clientId\":\"test-client\"}}";
            // System.out.println("Sending simple HELLO message: " + simpleJson);
            
            //clientWriter.println(helloJson);

            System.out.println("DONE PRINTING-------");
            

            clientWriter.close();
            Thread.sleep(1000); // Allow handler to detect closed stream
            handlerThread.join(1000); // Wait for handler thread to finish
            // Test successful
            System.out.println("Basic ClientHandler test completed");

            System.out.println("MAYBE HERE?");
            
        } catch (Exception e) {
            System.err.println("Test failed with exception: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Mock Socket class for testing
     */
    private static class MockSocket extends Socket {
        private final java.io.InputStream inputStream;
        private final java.io.OutputStream outputStream;
        
        public MockSocket(java.io.InputStream inputStream, java.io.OutputStream outputStream) {
            this.inputStream = inputStream;
            this.outputStream = outputStream;
        }
        
        @Override
        public java.io.InputStream getInputStream() {
            return inputStream;
        }
        
        @Override
        public java.io.OutputStream getOutputStream() {
            return outputStream;
        }
        
        @Override
        public boolean isClosed() {
            return false;
        }
        
        @Override
        public void close() throws IOException {
            // Do nothing
        }
    }
}