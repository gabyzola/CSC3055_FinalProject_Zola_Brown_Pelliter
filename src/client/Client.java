package client;

import merrimackutil.json.types.JSONObject;

import java.io.*;
import java.net.Socket;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Client {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 5000;
    private static final String TOTP_SECRET = "JBSWY3DPEHPK3PXP";

    private NetworkManager networkManager;
    private Scanner scanner;

    public Client() {
        scanner = new Scanner(System.in);
    }

    public void start() {
        try {
            Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
            System.out.println("[*] Connected to server at " + SERVER_ADDRESS + ":" + SERVER_PORT);

            networkManager = new NetworkManager(socket);

            authenticate();

            while (true) {
                showMenu();
                String choice = scanner.nextLine();
                handleClientAction(choice);
            }

        } catch (IOException e) {
            System.err.println("[!] Connection error: " + e.getMessage());
        } finally {
            cleanup();
        }
    }

    private void authenticate() throws IOException {
        System.out.println("[*] Authenticating...");

        System.out.print("Username: ");
        String username = scanner.nextLine().trim();

        System.out.print("Password: ");
        String password = scanner.nextLine().trim();

        String totp = generateTOTP(TOTP_SECRET);

        JSONObject authRequest = new JSONObject();
        authRequest.put("action", "authenticate");
        authRequest.put("username", username);
        authRequest.put("password", password);
        authRequest.put("totp", totp);

        networkManager.sendJSON(authRequest);
        JSONObject response = networkManager.receiveJSON();

        if (response.containsKey("status") && response.get("status").toString().equals("success"))
 {
            System.out.println("[+] Authentication successful.");
        } else {
            System.err.println("[!] Authentication failed: " + response.getString("error"));
            System.exit(1);
        }
    }

    private String generateTOTP(String base32Secret) {
        try {
            long timeStep = System.currentTimeMillis() / 1000 / 30;
            byte[] key = Base64.getDecoder().decode("cmF3LXNlY3JldC1wbGFjZWhvbGRlcg=="); // Simulated key
            byte[] data = new byte[8];
            for (int i = 7; timeStep > 0; i--) {
                data[i] = (byte) (timeStep & 0xFF);
                timeStep >>= 8;
            }

            SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(signKey);
            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0xF;
            int binary = ((hash[offset] & 0x7F) << 24) |
                         ((hash[offset + 1] & 0xFF) << 16) |
                         ((hash[offset + 2] & 0xFF) << 8) |
                         (hash[offset + 3] & 0xFF);

            int otp = binary % 1000000;
            return String.format("%06d", otp);
        } catch (Exception e) {
            System.err.println("[!] TOTP generation error: " + e.getMessage());
            return "000000";
        }
    }

    private void showMenu() {
        System.out.println("\n=== Client Menu ===");
        System.out.println("1. Upload File");
        System.out.println("2. Download File");
        System.out.println("3. View Blockchain Log");
        System.out.println("4. Exit");
        System.out.print("Choose an option: ");
    }

    private void handleClientAction(String choice) throws IOException {
        switch (choice) {
            case "1":
                System.out.print("Enter path to file for upload: ");
                String uploadPath = scanner.nextLine();
                uploadFile(uploadPath);
                break;
            case "2":
                System.out.print("Enter filename to download: ");
                String filename = scanner.nextLine();
                System.out.print("Save as: ");
                String savePath = scanner.nextLine();
                downloadFile(filename, savePath);
                break;
            case "3":
                viewBlockchainLog();
                break;
            case "4":
                System.out.println("Goodbye!");
                System.exit(0);
                break;
            default:
                System.out.println("[!] Invalid choice. Try again.");
        }
    }

    private void uploadFile(String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists()) {
            System.out.println("[!] File not found.");
            return;
        }

        JSONObject request = new JSONObject();
        request.put("action", "upload");
        request.put("filename", file.getName());
        request.put("filesize", file.length());

        networkManager.sendJSON(request);

        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file));
             OutputStream out = networkManager.getOutputStream()) {
            byte[] buffer = new byte[4096];
            int count;
            while ((count = bis.read(buffer)) > 0) {
                out.write(buffer, 0, count);
            }
            out.flush();
        }

        JSONObject response = networkManager.receiveJSON();
        System.out.println("[*] Upload result: " + response.toString());
    }

    private void downloadFile(String filename, String savePath) throws IOException {
        JSONObject request = new JSONObject();
        request.put("action", "download");
        request.put("filename", filename);

        networkManager.sendJSON(request);
        JSONObject response = networkManager.receiveJSON();

        if (response.get("status") != null && response.get("status").toString().equals("success")) {
            System.out.println("[+] Authentication successful.");
        } else {
            System.err.println("[!] Authentication failed: " + response.get("error"));
            System.exit(1);
        }

        long timestamp = (long) response.get("timestamp");
        long fileSize = (long) response.get("fileSize"); 
        
        try (InputStream in = networkManager.getInputStream();
             BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(savePath))) {
            byte[] buffer = new byte[4096];
            int read;
            long totalRead = 0;
        
            while (totalRead < fileSize && (read = in.read(buffer)) > 0) {
                bos.write(buffer, 0, read);
                totalRead += read;
            }
        }
        
        System.out.println("[*] Download complete: " + savePath); 
    }
        

    private void viewBlockchainLog() throws IOException {
        JSONObject request = new JSONObject();
        request.put("action", "view_log");

        networkManager.sendJSON(request);
        JSONObject response = networkManager.receiveJSON();

        if (response.containsKey("log"))
            {
            System.out.println("=== Blockchain Log ===");
            System.out.println(response.getString("log"));
        } else {
            System.out.println("[!] No log data available.");
        }
    }

    private void cleanup() {
        try {
            if (networkManager != null) networkManager.close();
            if (scanner != null) scanner.close();
        } catch (Exception e) {
            System.err.println("[!] Cleanup error: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        Client client = new Client();
        client.start();
    }
}
