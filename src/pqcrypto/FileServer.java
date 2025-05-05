package pqcrypto;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.security.GeneralSecurityException;

import common.Config;
import common.ConfigException;
import common.Constants;
import blockchain.BlockchainManager;

/**
 * main server application for the system
 * initializzes all components, listens for connections, and manages server lifecycle
 */
public class FileServer {
    
    private final Config config;
    private final CryptoManager cryptoManager;
    private final AuthManager authManager;
    private final FileManager fileManager;
    private final BlockchainManager blockchainManager;

    private ServerSocket serverSocket;
    private ExecutorService threadPool;
    private boolean running;

    private final int port;
    private final int maxConnections;
    private final String bindAddress;

    private ScheduledExecutorService maintenanceScheduler;
    private final int maintenanceIntervalMinutes;

    /**
     * main method, starts the file server
     * @param args
     */
    public static void main(String[] args) {

        System.out.println("FileServer: Starting PQ Blockchain File Server...");

        String configPath = "config/server_config.json";
        if (args.length > 0) {
            configPath = args[0];
        }

        try {
            // initialize with config 
            FileServer server = new FileServer(configPath);

            // set up shutdown hook for graceful termination
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("FileServer: Shutdown signal received, stopping server...");
                server.stop();
            }));
        } catch (ConfigException e) {
            System.err.println("FileServer: Configuration error: " + e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            System.err.println("File Server: Server initialization error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * constructs a new file server with the specified config file 
     * @param configPath
     * @throws ConfigException
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public FileServer(String configPath) throws ConfigException, IOException, GeneralSecurityException {

        // load config
        System.out.println("FileServer: loading config from: " + configPath);
        this.config = new Config("config.system_config.json", configPath);

        // extract server config 
        this.port = config.getInt("server.port", 5001);
        this.maxConnections = config.getInt("server.max_connections", 100);
        this.bindAddress = config.getString("server.bind_address", "0.0.0.0");
        int threadPoolSize = config.getInt("server.thread_pool_size", 10);

        System.out.println("FileServer: Initializing server on " + bindAddress + ":" + port);
        System.out.println("FileServer: Thread pool size: " + threadPoolSize);
        System.out.println("FileServer: Max connections: " + maxConnections);

        // initialize thread pool
        this.threadPool = Executors.newFixedThreadPool(threadPoolSize);

        // initialize components
        System.out.println("FileServer: Initializing crypto components...");
        this.cryptoManager = new CryptoManager(config);

        System.out.println("FileServer: Initializing blockchain...");
        this.blockchainManager = new BlockchainManager(config);

        System.out.println("FileServer: Initializing authentication manager...");
        this.authManager = new AuthManager(config, cryptoManager);

        System.out.println("FileServer: Initializing file manager...");
        this.fileManager = new FileManager(config, cryptoManager, blockchainManager, authManager);

        this.running = false;

        this.maintenanceIntervalMinutes = config.getInt("server.maintenance_interval_mins", 30);
        this.maintenanceScheduler = Executors.newScheduledThreadPool(1);
    } 

    /**
     * starts the server
     * @throws IOException
     */
    public void start() throws IOException {
        if (running) {
            System.out.println("FileServer: Server already runnning");
            return; 
        }

        // create server socket
        serverSocket = new ServerSocket(port, maxConnections);
        running = true;

        System.out.println("FileServer: Server started and lisening on port " + port);

        maintenanceScheduler.scheduleAtFixedRate(this::performMaintenance, maintenanceIntervalMinutes, maintenanceIntervalMinutes, TimeUnit.MINUTES);
        System.out.println("FileServer: Maintenance tasks schedules every " + maintenanceIntervalMinutes + " minutes");

        // main accept loop
        while (running) {
            try {

                // accept new connection
                Socket clientSocket = serverSocket.accept();

                // create client handler and submit to thread pool
                ClientHandler handler = new ClientHandler(clientSocket, config, cryptoManager, authManager, fileManager, blockchainManager);
                threadPool.submit(handler);
                System.out.println("FileServer: New coonnection accepted from: " + clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort());

            } catch (IOException e) {
                if (running) {
                    // only log errors if we're supposed to be running 
                    System.err.println("FileServer: Error accepting connections: "+ e.getMessage());
                }
            }
        }
    }

    /**
     * stops server ✨gracefully✨
     */
    public void stop() {
        if (!running) {
            System.out.println("FileServer: server already stopped");
            return;
        }

        running = false; 
        System.out.println("FileServer: Stopping the server...");

        // stop the maintenance scheduler
        maintenanceScheduler.shutdown();
        try {
            if (!maintenanceScheduler.awaitTermination(10, TimeUnit.SECONDS)) {
                maintenanceScheduler.shutdownNow();
            } 
        } catch (InterruptedException e) {
            System.out.println("FileServer: interruped exception");
            maintenanceScheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }

        // close server socket
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            } 
        } catch (IOException e) {
            System.err.println("FileServer: Error closing server sockete: " + e.getMessage());
        }

        // shutdown thread pool
        threadPool.shutdown();
        try {
            //wait for active tasks to terminate
            if (!threadPool.awaitTermination(Constants.THREAD_POOL_KEEP_ALIVE_SECONDS, TimeUnit.SECONDS)) {
                // force shutdown
                threadPool.shutdown();
            }
        } catch (InterruptedException e) {
            threadPool.shutdown();
            Thread.currentThread().interrupt();
        }

        // clean up sessions 
        System.out.println("FileServer: cleaning up zctive sessions...");
        // authManager handles this, don't need to call anything

        // final shutdown msg
        System.out.println("FileServer: Server stopped successfully");
    }

    /**
     * performs periodic maintenance tasks
     */
    private void performMaintenance() {
        try {
            // clean up expired sessions
            authManager.cleanupExpiredSessions();
            // clean up orphaned files
            int filesRemoved = fileManager.cleanupOrphanedFiles();

            System.out.println("FileServer: Maintenance complete: removed " + filesRemoved + " orphaned files");
        } catch (Exception e) {
            System.err.println("FileServer: Error during maintenance: " + e.getMessage());
        }
    }

}
