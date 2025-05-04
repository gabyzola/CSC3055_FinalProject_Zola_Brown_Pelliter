package client;

import merrimackutil.json.types.JSONObject;

import java.io.*;
import java.net.Socket;

public class NetworkManager {
    private final Socket socket;
    private final BufferedReader in;
    private final BufferedWriter out;

    public NetworkManager(Socket socket) throws IOException {
        this.socket = socket;
        this.in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        this.out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
    }

    public void sendJSON(JSONObject json) throws IOException {
        out.write(json.toString());
        out.newLine();
        out.flush();
    }

    public JSONObject receiveJSON() throws IOException {
        String line = in.readLine();
        if (line != null) {
            return new JSONObject();
        }
        return new JSONObject(); // Return empty JSON if null
    }

    // ✅ Add these two methods to expose the raw streams if needed:
    public InputStream getInputStream() throws IOException {
        return socket.getInputStream();
    }

    public OutputStream getOutputStream() throws IOException {
        return socket.getOutputStream();
    }

    public void close() throws IOException {
        socket.close();
        in.close();
        out.close();
    }
}

