package client;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

import java.io.*;
import java.net.Socket;

public class NetworkManager {
    private Socket socket;
    private BufferedReader reader;
    private BufferedWriter writer;

    public NetworkManager(Socket socket) throws IOException {
        this.socket = socket;
        this.reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        this.writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
    }

    public void sendJSON(JSONObject json) throws IOException {
        writer.write(json.toString());
        writer.newLine();
        writer.flush();
    }

    public JSONObject receiveJSON() throws IOException {
        String line = reader.readLine();
        if (line != null && !line.isEmpty()) {
            return new JSONObject();
        }
        return new JSONObject(); 
    }

    public void close() {
        try {
            if (reader != null) reader.close();
            if (writer != null) writer.close();
            if (socket != null) socket.close();
        } catch (IOException e) {
            System.err.println("[!] Network cleanup error: " + e.getMessage());
        }
    }
}
