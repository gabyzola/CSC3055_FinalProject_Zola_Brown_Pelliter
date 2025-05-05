package pqcrypto;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.GeneralSecurityException;

import common.Config;
import common.Constants;
import common.Message;
import blockchain.BlockchainManager;

import merrimackutil.json.parser.JSONParser;
import merrimackutil.json.types.JSONObject;
/**
 * handles inividual client connections 
 * processes incoming messages, enforeces security protocol, and routes requests to the appropriate managers (Auth, File, Blockchain)
 */
public class ClientHandler implements Runnable {
    
    private final Socket clientSocket;
    private final Config config; 
    private final CryptoManager cryptoManager;
    private final AuthManager authManager;
    private final FileManager fileManager;
    private final BlockchainManager blockchainManager;

    private BufferedReader input;
    private PrintWriter output;
    private String sessionId;
    private String clientAddress;
    private boolean running;

    private enum State {
        INITIAL,
        AUTHENTICATING,
        TOTP_VERIFICATION,
        KEY_EXCHANGE,
        AUTHENTICATED,
        CLOSED
    }

    private State currentState; 

    public ClientHandler(Socket clienSocket, Config config, CryptoManager cryptoManager, AuthManager authManager, FileManager fileManager, BlockchainManager blockchainManager) {
        this.clientSocket = clienSocket;
        this.config = config;
        this.cryptoManager = cryptoManager;
        this.authManager = authManager;
        this.fileManager = fileManager;
        this.blockchainManager = blockchainManager;
        this.sessionId = null;
        this.currentState = State.INITIAL;
        this.running = true;
        this.clientAddress = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();

        System.out.println("ClientHandler: new connection from " + clientAddress);
    }

    /**
     * main processing loop for the client connection
     */
    @Override
    public void run() {
        try {
            // set up connection streams
            input = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            output = new PrintWriter(clientSocket.getOutputStream(), true);

            // process messages until connection is closed
            while (running) {
                String jsonMessage = input.readLine();

                // check for connection closed
                if (jsonMessage == null) {
                    System.out.println("ClientHandler: connection closed by client " + clientAddress);
                    break;
                }

                // process the message
                processMessage(jsonMessage);
            }
        } catch (IOException e) {
            System.out.println("ClientConnection: connection error: " + e.getMessage());
        } finally {
            cleanup();
        }
    }

    private void processMessage(String jsonMessage) {
        Message response = null;
        try {
            // parse the message
            JSONParser parser = new JSONParser(jsonMessage);
            Message message = new Message((JSONObject) parser.parse().evaluate());
            
            // validate session ID if its present
            if (message.getSessionId() != null && !message.getSessionId().isEmpty()) {
                if (sessionId != null && !sessionId.equals(message.getSessionId())) {
                    response = new Message(Constants.MSG_TYPE_ERROR);
                    response.addPayload(Constants.FIELD_ERROR_CODE, Constants.ERROR_SESSION_EXPIRED);
                    response.addPayload(Constants.FIELD_ERROR_MESSAGE, "ClientHandler: invalid session id");
                    sendResponse(response);
                    return;
                }
                // set sessio id if we dont have one yet 
                if (sessionId == null) {
                    sessionId = message.getSessionId();
                }
            }
            
            // special handling for GOODBYE
            if (Constants.MSG_TYPE_GOODBYE.equals(message.getType())) {
                System.out.println("ClientHandler: handling goodbye");
                handleGoodbye(message);
                return;
            }

            // validate message based on current state
            if (!validateMessageForState(message)) {
                response = new Message(Constants.MSG_TYPE_ERROR);
                response.setSessionId(sessionId);
                response.addPayload(Constants.FIELD_ERROR_CODE, Constants.ERROR_PROTOCOL_VERSION);
                response.addPayload(Constants.FIELD_ERROR_MESSAGE, "ClientHandler: invalid message for current state");
                sendResponse(response);
                return;
            }

            // validate nonce if required
            if (currentState != State.INITIAL && !validateNonce(message)) {
                response = new Message(Constants.MSG_TYPE_ERROR);
                response.setSessionId(sessionId);
                response.addPayload(Constants.FIELD_ERROR_CODE, Constants.ERROR_AUTHENTICATION_FALED);
                response.addPayload(Constants.FIELD_ERROR_MESSAGE, "ClientHandler: invalid nonce");
                sendResponse(response);
                return;
            }

            // handle message based on type
            response = routeMessage(message);

        } catch (Exception e) {
            System.err.println("ClientHandler: Message processing error: " + e.getMessage());
            e.printStackTrace();

            response = new Message(Constants.MSG_TYPE_ERROR);
            if (sessionId != null) {
                response.setSessionId(sessionId);
            }            
            response.addPayload(Constants.FIELD_ERROR_CODE, Constants.ERROR_SERVER_INTERNAL);
            response.addPayload(Constants.FIELD_ERROR_MESSAGE, "ClientHandler: Server error: " + e.getMessage());
        }

        // sedn response if we have one
        if (response != null) {
            sendResponse(response);
        }
    }

    private Message routeMessage(Message message) throws GeneralSecurityException {
        String messageType = message.getType();

        // initial connection message
        if (Constants.MSG_TYPE_HELLO.equals(messageType)) {
            return handleHello(message);
        }

        // authentication flow
        if (Constants.MSG_TYPE_AUTH_REQUEST.equals(messageType)) {
            return handleAuthRequest(message);
        }

        if (Constants.MSG_TYPE_TOTP_RESPONSE.equals(messageType)) {
            return handleTotpResponse(message);
        }

        if (Constants.MSG_TYPE_KEY_EXCHANGE.equals(messageType)) {
            return handleKeyExchange(message);
        }

        // authenticated operations
        if (currentState == State.AUTHENTICATED) {

            // verify msg signature for authenticated requests
            if (message.getSignature() != null) {
                boolean validSignature = verifyMessageSignature(message);
                if (!validSignature) {
                    Message error = new Message(Constants.MSG_TYPE_ERROR);
                    error.setSessionId(sessionId);
                    error.addPayload(Constants.FIELD_ERROR_CODE, Constants.ERROR_AUTHENTICATION_FALED);
                    error.addPayload(Constants.FIELD_ERROR_CODE, "ClientHandler: invalid message signature");
                    return error;
                }
            }

            // file operations
            if (Constants.MSG_TYPE_FILE_UPLOAD.equals(messageType)) {
                return fileManager.handleFileUploadRequest(message, sessionId);
            }

            if (Constants.MSG_TYPE_FILE_DOWNLOAD.equals(messageType)) {
                return fileManager.handleFileDownloadRequest(message, sessionId);
            }

            if (Constants.MSG_TYPE_FILE_LIST.equals(messageType)) {
                return fileManager.handleFileListRequest(message, sessionId);
            }
            
            // blockchain operations
            if (Constants.MSG_TYPE_BLOCKCHAIN_QUERY.equals(messageType)) {
                return handleBlockchainQuery(message);
            }
        }

        // unrecognized message type
        Message error = new Message(Constants.MSG_TYPE_ERROR);
        error.setSessionId(sessionId);
        error.addPayload(Constants.FIELD_ERROR_CODE, Constants.ERROR_PROTOCOL_VERSION);
        error.addPayload(Constants.FIELD_ERROR_MESSAGE, "ClientHandler: unsupported message type: " + messageType);
        return error;
    }

    /**
     * handles the initial hello message
     * @param message
     * @return
     */
    private Message handleHello(Message message) {
        System.out.println("ClientHandler: hello from " + clientAddress);

        // creaete response with server's protocol version
        Message response = new Message(Constants.MSG_TYPE_HELLO);
        response.addPayload("protocol_version", Constants.PROTOCOL_VERSION);
        response.setNonce(cryptoManager.generateNonce());

        // update state
        currentState = State.AUTHENTICATING;

        return response;
    }

    /**
     * handles an authentication request
     * @param message
     * @return
     */
    private Message handleAuthRequest(Message message) {

        System.out.println("ClientHandler: auth request from " + clientAddress);

        // forward to auth manager
        Message response = authManager.handleLoginRequest(message);

        // update state if successful
        if (Constants.MSG_TYPE_TOTP_CHALLENGE.equals(response.getType())) {
            currentState = State.TOTP_VERIFICATION;
            sessionId = response.getSessionId(); // save the new session id
        }
        return response;
    }

    /**
     * handles a TOTP verification response
     * @param message
     * @return
     */
    private Message handleTotpResponse(Message message) {
        System.out.println("ClientHandler: TOTP response frm " + clientAddress);

        // forward to auth manager
        Message response = authManager.handleTotpResponse(message);

        // update if successful
        if (Constants.MSG_TYPE_KEY_EXCHANGE.equals(response.getType())) {
            currentState = State.KEY_EXCHANGE;
        }

        return response;
    }

    private Message handleKeyExchange(Message message) {
        System.out.println("ClientHandler: Key exchange from " + clientAddress);

        // forward to auth manager
        Message response = authManager.completeKeyExchange(message);

        // update if successful
        if ("AUTH_SUCCESS".equals(response.getType())) {
            currentState = State.AUTHENTICATED;
            System.out.println("ClientHandler: Client " + clientAddress + " authenticated with session " + sessionId);
        }
        return response;
    }

    /**
     * handles a blockchain query
     * @param message
     * @return
     */
    private Message handleBlockchainQuery(Message message) {
        System.out.println("ClientHandler: blockchain query from " + clientAddress);

        String queryType = message.getPayloadString("query_type");

        if (queryType == null) {
            Message error = new Message(Constants.MSG_TYPE_ERROR);
            error.setSessionId(sessionId);
            error.addPayload(Constants.FIELD_ERROR_CODE, Constants.ERROR_BLOCKCHAIN_INVALID);
            error.addPayload(Constants.FIELD_ERROR_MESSAGE, "ClientHandler: missing query type");
            return error;
        }

        try {
            Message response = new Message("BLOCKCHAIN_RESULT", sessionId);
            response.setNonce(cryptoManager.generateNonce());

            if ("get_all_blocks".equals(queryType)) {
                response.addPayload("blocks", blockchainManager.getAllBlocks());
            } else if ("get_block_by_hash".equals(queryType)) {
                String blockHash = message.getPayloadString("block_hash");
                response.addPayload("block", blockchainManager.getBlockByHash(blockHash));
            } else if ("get_transaction_by_hash".equals(queryType)) {
                String txHash = message.getPayloadString("transaction_hash");
                response.addPayload("transaction", blockchainManager.getTransactionByHash(txHash));
            } else if ("get_file_transactons".equals(queryType)) {
                String fileHash = message.getPayloadString("file_hash");
                response.addPayload("transactions", blockchainManager.getFileTransactions(fileHash));
            } else if ("get_user_transactions".equals(queryType)) {
                String username = message.getPayloadString("username");
                response.addPayload("transactions", blockchainManager.getUserTransactions(username));
            } else {
                Message error = new Message(Constants.MSG_TYPE_ERROR);
                error.setSessionId(sessionId);
                error.addPayload(Constants.FIELD_ERROR_CODE, Constants.ERROR_BLOCKCHAIN_INVALID);
                error.addPayload(Constants.FIELD_ERROR_MESSAGE, "ClientHandler: unsupported query type: " + queryType);
                return error;
            }

            // sign the response
            byte[] dataToSign = response.getDataToSign();
            byte[] signature = cryptoManager.sign(dataToSign);
            response.setSignature(signature);

            return response; 

        } catch (Exception e) {
            Message error = new Message(Constants.MSG_TYPE_ERROR);
            error.setSessionId(sessionId);
            error.addPayload(Constants.FIELD_ERROR_CODE, Constants.ERROR_BLOCKCHAIN_INVALID);
            error.addPayload(Constants.FIELD_ERROR_MESSAGE, "ClientHandler: blockchain query failed: " + e.getMessage());
            return error; 
        }
    }

    /**
     * handles goodbye messages
     * @param message
     */
    private void handleGoodbye(Message message) {
        System.out.println("ClientHandler: goobye from: " + clientAddress);

        // close the session
        if (sessionId != null) {
            authManager.closeSession(sessionId);
        }

        // send goodbye response
        Message response = new Message(Constants.MSG_TYPE_GOODBYE);
        if (sessionId != null) {
            response.setSessionId(sessionId);
        }

        sendResponse(response);

        // update state and stop processing
        currentState = State.CLOSED;
        running = false;
    }

    /**
     * validates that a messge is appropriate for the current protocol state
     * @param message
     * @return
     */
    private boolean validateMessageForState(Message message) {
        String messageType = message.getType();

        switch (currentState) {
            case INITIAL:
                return Constants.MSG_TYPE_HELLO.equals(messageType);
            case AUTHENTICATING:
                return Constants.MSG_TYPE_AUTH_REQUEST.equals(messageType) || Constants.MSG_TYPE_GOODBYE.equals(messageType);
            case TOTP_VERIFICATION:
                return Constants.MSG_TYPE_TOTP_RESPONSE.equals(messageType) || Constants.MSG_TYPE_GOODBYE.equals(messageType);
            case KEY_EXCHANGE:
                return Constants.MSG_TYPE_KEY_EXCHANGE.equals(messageType) || Constants.MSG_TYPE_GOODBYE.equals(messageType);
            case AUTHENTICATED: // all msg types are allows in an authenticated state
                return true;
            case CLOSED:
                return false;
            default: 
            return false;
        }
    }

    /**
     * validate a message nonce to prevent replay attacks
     * @param message
     * @return
     */
    private boolean validateNonce(Message message) {
        byte[] nonce = message.getNonce();

        if (nonce == null) {
            return false;
        }

        return cryptoManager.validateNonce(nonce);
    }

    /**
     * verifies a message signature
     * @param message
     * @return
     */
    private boolean verifyMessageSignature(Message message) {
        try {
            byte[] signature = message.getSignature();
            byte[] dataToVerify = message.getDataToSign();

            if (signature == null || dataToVerify == null) {
                System.out.println("ClientHandler: sig || dataToVerify -> is null");
                return false;
            }

            // for server side verification we would need to client's pubkic key, this is a simplified implementation
            return true;
        } catch (Exception e) {
            System.err.println("ClientHandlerL signature verification error: " + e.getMessage());
            return false;
        }
    }

    /**
     * sends a response message to the client
     * @param response
     */
    private void sendResponse(Message response) {
        try {
            // add a nonce if not present
            if (response.getNonce() == null) {
                response.setNonce(cryptoManager.generateNonce());
            }

            // set session id if available
            if (sessionId != null && response.getSessionId() == null) {
                response.setSessionId(sessionId);
            }

            // sign the response if authenticated and not already signed
            if (currentState == State.AUTHENTICATED && response.getSignature() == null) {
                byte[] dataToSign = response.getDataToSign();
                byte[] signature =cryptoManager.sign(dataToSign);
                response.setSignature(signature);
            }

            // send the response
            output.println(response.serialize());
        } catch (Exception e) {
            System.err.println("ClientHandler: error sending response: " + e.getMessage());
        }
    }

    private void cleanup() {
        try {
            // close the session if still active
            if (sessionId != null) {
                authManager.closeSession(sessionId);
            }

            // close streams and socket
            if (input != null) {
                input.close();
            }
            if (output != null) {
                output.close();
            }
            if (clientSocket != null && !clientSocket.isClosed()) {
                clientSocket.close();
            }

            System.out.println("ClientHandler: cleaned up connection from: " + clientAddress);
        } catch(IOException e) {
            System.err.println("ClientHandler: error during cleanup: " + e.getMessage());
        }
    }
}
