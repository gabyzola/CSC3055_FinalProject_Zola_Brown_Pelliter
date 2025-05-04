package common;

import java.io.InvalidObjectException;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

/**
 * represents protocol messages exchanged between the client and server
 */
public class Message implements JSONSerializable {
    
    private String type; 
    private String sessionId;
    private long timestamp;
    private byte[] nonce; 

    // message content
    private Map<String, Object> payload;

    // security fields
    private byte[] signature;

    /**
     * creates a new empty message
     */
    public Message() {
        this.type = "";
        this.sessionId = "";
        this.timestamp = Instant.now().getEpochSecond();
        this.nonce = null;
        this.payload = new HashMap<>();
        this.signature = null;
    }

    /**
     * creates a new message with the specified type
     * @param type
     */
    public Message(String type) {
        this();
        this.type = type;
    }

    /**
     * creates a new message with the specified type and session ID
     * @param type
     * @param sessionId
     */
    public Message(String type, String sessionId) {
        this(type);
        this.sessionId = sessionId; 
    }

    /**
     * creeates a message from a JSON object (used for deserialization)
     * @param obj
     * @throws InvalidObjectException
     */
    public Message(JSONObject obj) throws InvalidObjectException {
        deserialize(obj);
    }

    /**
     * gets the message type
     * @return
     */
    public String getType() {
        return this.type; 
    }

    /**
     * sets the message type
     * @param type
     */
    public void setType(String type) {
        this.type = type; 
    }

    /**
     * gets the sessionId
     * @return
     */
    public String getSessionId() {
        return this.sessionId; 
    }

    /**
     * sets the sessionId
     * @param type
     */
    public void setSessionId(String sessionId) {
        this.sessionId = sessionId; 
    }

    /**
     * gets the timestamp
     * @return
     */
    public long getTimeStamp() {
        return this.timestamp; 
    }

    /**
     * sets the timestamp
     * @param type
     */
    public void setTimeStamp(long timestamp) {
        this.timestamp = timestamp; 
    }

    /**
     * gets the nonce
     * @return
     */
    public byte[] getNonce() {
        return this.nonce; 
    }

    /**
     * sets the nonce
     */
    public void setNonce(byte[] nonce) {
        this.nonce = nonce; 
    }

    /**
     * gets the message type
     * @return
     */
    public byte[] getSignature() {
        return this.signature; 
    }

    /**
     * sets the message type
     * @param type
     */
    public void setSignature(byte[] signature) {
        this.signature = signature; 
    }

    /**
     * gets the payload
     * @return
     */
    public Map<String, Object> getPayload() {
        return this.payload;
    }

    /**
     * sets the payload 
     * @param payload
     */
    public void setPayload(Map<String, Object> payload) {
        this.payload = payload;
    }

    /**
     * adds am entry to the payload 
     * @param key
     * @param value
     */
    public void addPayload(String key, Object value) {
        this.payload.put(key, value);
    }

    /**
     * gets a field from the payload 
     * @param key
     * @return
     */
    public Object getPayloadField(String key) {
        return this.payload.get(key);
    }

    /**
     * gets a string field from the payload
     * @param key
     * @return
     */
    public String getPayloadString(String key) {
        Object value = this.payload.get(key);
        return (value instanceof String) ? (String) value : null;
    }

    /**
     * gets an integer field from the payload 
     * @param key
     * @return
     */
    public Integer getPayloadInteger(String key) {
        Object value = this.payload.get(key);
        if (value instanceof Integer) {
            return (Integer) value;
        } else if (value instanceof Number) {
            return ((Number) value).intValue();
        } 
        return null;
    }

    /**
     * gets a byte array field from the payload
     * @param key
     * @return
     */
    public byte[] getPayloadBytes(String key) {
        String value = getPayloadString(key);
        if (value == null) {
            return null;
        }
        try {            
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            System.out.println("Message: ERROR: couldnt decode value into base 64");
            return null; 
        }
    }

    /**
     * creates a response message for this message
     * @param responseType
     * @return
     */
    public Message createResponse(String responseType) {
        Message response = new Message(responseType, this.sessionId);
        return response; 
    }

    /**
     * create an error response message
     * @param errorCode
     * @param errorMessage
     * @return
     */
    public Message createErrorResponse(int errorCode, String errorMessage) {
        Message error = new Message(Constants.MSG_TYPE_ERROR, this.sessionId);
        error.addPayload(Constants.FIELD_ERROR_CODE, errorCode);
        error.addPayload(Constants.FIELD_ERROR_MESSAGE, errorMessage);
        return error; 
    }

    /**
     * generates data to be signed 
     * @return
     */
    public byte[] getDataToSign() {
        JSONObject obj = new JSONObject();

        obj.put(Constants.FIELD_MESSAGE_TYPE, this.type);
        obj.put(Constants.FIELD_SESSION_ID, this.sessionId);
        obj.put(Constants.FIELD_TIMESTAMP, this.timestamp);

        if (nonce != null) {
            obj.put(Constants.FIELD_NONCE, Base64.getEncoder().encodeToString(this.nonce)); 
        }

        if (!payload.isEmpty()) {
            JSONObject payloadObj = new JSONObject();
            for (Map.Entry<String, Object> entry : payload.entrySet()) {
                if (entry.getValue() instanceof byte[]) {
                    payloadObj.put(entry.getKey(), Base64.getEncoder().encodeToString((byte[]) entry.getValue()));
                } else {
                    payloadObj.put(entry.getKey(), entry.getValue());
                }
            }
            obj.put(Constants.FIELD_PAYLOAD, payloadObj);
        } 
        return obj.toJSON().getBytes();
    }

    /**
     * creates a new random session ID
     * @return
     */
    public static String generateSessionId() {
        return UUID.randomUUID().toString();
    }

    /**
     * serializes this message to a JSON object
     * @return
     */
    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();

        obj.put(Constants.FIELD_MESSAGE_TYPE, this.type);
        obj.put(Constants.FIELD_SESSION_ID, this.sessionId);
        obj.put(Constants.FIELD_TIMESTAMP, this.timestamp);

        if (nonce != null) {
            obj.put(Constants.FIELD_NONCE, Base64.getEncoder().encodeToString(this.nonce)); 
        }

        if (signature != null) {
            obj.put(Constants.FIELD_SIGNATURE, Base64.getEncoder().encodeToString(this.signature)); 

        }

        if (!payload.isEmpty()) {
            JSONObject payloadObj = new JSONObject();
            for (Map.Entry<String, Object> entry : payload.entrySet()) {
                if (entry.getValue() instanceof byte[]) {
                    payloadObj.put(entry.getKey(), Base64.getEncoder().encodeToString((byte[]) entry.getValue()));
                } else {
                    payloadObj.put(entry.getKey(), entry.getValue());
                }
            }
            obj.put(Constants.FIELD_PAYLOAD, payloadObj);
        } 
        return obj; 
    }

    /**
     * deserializes a JSON object into this message
     * @param obj
     * @throws InvalidObjectException
     */
    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        if (obj instanceof JSONObject) {
            JSONObject messageObj = (JSONObject) obj;

            // required fields
            this.type = messageObj.getString(Constants.FIELD_MESSAGE_TYPE);
            if (this.type == null) {
                throw new InvalidObjectException("Message: ERROR: Messge type is required");
            }

            // optional fields with defaults
            this.sessionId = messageObj.getString(Constants.FIELD_SESSION_ID);
            if (this.sessionId == null) {
                this.sessionId = "";
            }

            Integer timestamp = messageObj.getInt(Constants.FIELD_TIMESTAMP);
            this.timestamp = (timestamp != null) ? timestamp : Instant.now().getEpochSecond();

            // security fields
            String nonceStr = messageObj.getString(Constants.FIELD_NONCE);
            if (nonceStr != null) {
                this.nonce = Base64.getDecoder().decode(nonceStr);
            }

            String signatureStr = messageObj.getString(Constants.FIELD_SIGNATURE);
            if (nonceStr != null) {
                this.nonce = Base64.getDecoder().decode(signatureStr);
            }

            // payload
            this.payload = new HashMap<>();
            JSONObject payloadObj = messageObj.getObject(Constants.FIELD_PAYLOAD);
            if (payloadObj != null) {
                for (String key : payloadObj.keySet()) {
                    Object value = payloadObj.get(key);
                    if (value instanceof String && isBase64((String) value)) {
                        try {
                            this.payload.put(key, Base64.getDecoder().decode((String) value));
                        } catch (IllegalArgumentException e) {
                            this.payload.put(key, value); // if its not a b64, store it as a string
                        }
                    } else {
                        this.payload.put(key, value);
                    }
                }
            } else {}
                throw new InvalidObjectException("Message: ERROR: expected JSON object for Message deserialization");
            }
        }

        /**
         * checks if a string is likely Base64 encoded
         * @param str
         * @return
         */
        private boolean isBase64(String str) {
            if (str.length() < 8 || str.length() % 4 != 0) {
                return false; 
            }

            return str.matches("^[A-Za-z0-9+/]*={0,2}$");
        }

        /**
         * serializes this message to a JSON string
         * @return
         */
        @Override
        public String serialize() {
            return toJSONType().toJSON();
        }

        /**
         * returns a string representation of this message
         */
        @Override
        public String toString() {
            return "Message[type=" + type + 
               ", sessionId=" + sessionId + 
               ", timestamp=" + timestamp + 
               ", payloadSize=" + payload.size() + 
               ", hasNonce=" + (nonce != null) + 
               ", hasSignature=" + (signature != null) + 
               "]";
        }

    }
