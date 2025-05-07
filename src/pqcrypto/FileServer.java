package pqcrypto;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import blockchain.BlockchainManager;
import common.Config;
import common.Constants;

/**
 * Main server application for the PQ Blockchain File Sharing system.
 */
public class FileServer {
    private int port;
    private int maxConnections;
    private int threadPoolSize;
    private boolean running = false;
    
    private ServerSocket serverSocket;
    private ExecutorService threadPool;
    
    private CryptoManager cryptoManager;
    private AuthManager authManager;
    private FileManager fileManager;
    private BlockchainManager blockchainManager;
    
    /**
     * Create a new FileServer
     * 
     * @param configPath Path to configuration file (optional)
     * @throws Exception If initialization fails
     */
    public FileServer(String configPath) throws Exception {
        // Load configuration
        Config config;
        if (configPath != null && new File(configPath).exists()) {
            config = Config.getInstance(configPath);
        } else {
            config = Config.getInstance(true); // Default server config
        }
        
        // Load system configuration
        Config systemConfig = Config.getSystemConfig();
        
        // Initialize server parameters
        this.port = config.getInt("server.port", Constants.DEFAULT_SERVER_PORT);
        this.maxConnections = config.getInt("server.max_connections", 100);
        this.threadPoolSize = config.getInt("server.thread_pool_size", 10);
        
        // Initialize components
        this.cryptoManager = new CryptoManager(config);
        this.blockchainManager = new BlockchainManager(config);
        this.authManager = new AuthManager(cryptoManager, config);
        this.fileManager = new FileManager(config, cryptoManager, blockchainManager);
        
        // Create thread pool
        this.threadPool = Executors.newFixedThreadPool(threadPoolSize);
    }
    
    /**
     * Start the server
     * 
     * @throws IOException If server socket binding fails
     */
    public void start() throws IOException {
        if (running) {
            return;
        }
        
        // Create server socket
        serverSocket = new ServerSocket(port, maxConnections);
        running = true;
        
        System.out.println("Server started on port " + port);
        
        // Accept connections
        new Thread(() -> acceptConnections()).start();
    }
    
    /**
     * Accept client connections
     */
    private void acceptConnections() {
        while (running) {
            try {
                // Accept connection
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected: " + clientSocket.getInetAddress());
                
                // Create client handler
                ClientHandler handler = new ClientHandler(
                    clientSocket,
                    cryptoManager,
                    authManager,
                    fileManager,
                    blockchainManager
                );
                
                // Submit to thread pool
                threadPool.submit(handler);
            } catch (IOException e) {
                if (running) {
                    System.err.println("Error accepting connection: " + e.getMessage());
                }
            }
        }
    }
    
    /**
     * Stop the server
     */
    public void stop() {
        if (!running) {
            return;
        }
        
        running = false;
        
        try {
            // Close server socket
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
            
            // Shutdown thread pool
            if (threadPool != null && !threadPool.isShutdown()) {
                threadPool.shutdown();
            }
            
            System.out.println("Server stopped");
        } catch (IOException e) {
            System.err.println("Error stopping server: " + e.getMessage());
        }
    }
    
    /**
     * Main method
     * 
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        try {
            // Parse arguments
            String configPath = null;
            
            for (int i = 0; i < args.length; i++) {
                if (("-c".equals(args[i]) || "--config".equals(args[i])) && i + 1 < args.length) {
                    configPath = args[i + 1];
                    i++;
                } else if ("-h".equals(args[i]) || "--help".equals(args[i])) {
                    printHelp();
                    return;
                }
            }
            
            // Create and start server
            FileServer server = new FileServer(configPath);
            server.start();
            
            // Add shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(() -> server.stop()));
        } catch (Exception e) {
            System.err.println("Error starting server: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    /**
     * Print help message
     */
    private static void printHelp() {
        System.out.println("usage:");
        System.out.println("server");
        System.out.println("server --config <configfile>");
        System.out.println("server --help");
        System.out.println("options:");
        System.out.println("-c, --config Set the config file");
        System.out.println("-h, --help Display the help");
    }
}