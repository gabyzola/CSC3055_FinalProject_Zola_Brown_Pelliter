package common;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

/**
 * Represents a protocol message for client-server communication.
 */
public class Message implements JSONSerializable {
    private String type;
    private String version;
    private String nonce;
    private Map<String, Object> headers;
    private Map<String, Object> payload;
    private String signature;
    
    /**
     * Create a new empty message
     */
    public Message() {
        this.version = Constants.PROTOCOL_VERSION;
        this.headers = new HashMap<>();
        this.payload = new HashMap<>();
        this.nonce = generateNonce();
    }
    
    /**
     * Create a new message with the specified type
     * 
     * @param type The message type
     */
    public Message(String type) {
        this();
        this.type = type;
    }
    
    /**
     * Create a message from a JSONObject
     * 
     * @param jsonObject The JSONObject to parse
     */
    public Message(JSONObject jsonObject) {
        this.headers = new HashMap<>();
        this.payload = new HashMap<>();
        
        try {
            this.type = (String) jsonObject.get("type");
            this.version = (String) jsonObject.get("version");
            this.nonce = (String) jsonObject.get("nonce");
            this.signature = (String) jsonObject.get("signature");
            
            JSONObject headersObj = (JSONObject) jsonObject.get("headers");
            if (headersObj != null) {
                for (Object key : headersObj.keySet()) {
                    if (key != null) {
                        Object value = headersObj.get(key);
                        if (value != null) {
                            headers.put((String) key, value);
                        } else {
                            System.err.println("Warning: Null value for header key: " + key);
                        }
                    } else {
                        System.err.println("Warning: Null key in headers object");
                    }
                }
            }
            
            JSONObject payloadObj = (JSONObject) jsonObject.get("payload");
            if (payloadObj != null) {
                for (Object key : payloadObj.keySet()) {
                    if (key != null) {
                        Object value = payloadObj.get(key);
                        if (value != null) {
                            payload.put((String) key, value);
                        } else {
                            System.err.println("Warning: Null value for payload key: " + key);
                        }
                    } else {
                        System.err.println("Warning: Null key in payload object");
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error in Message constructor: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Get the message type
     * 
     * @return The message type
     */
    public String getType() {
        return type;
    }
    
    /**
     * Set the message type
     * 
     * @param type The message type
     */
    public void setType(String type) {
        this.type = type;
    }
    
    /**
     * Get the protocol version
     * 
     * @return The protocol version
     */
    public String getVersion() {
        return version;
    }

    public void setVersion(String newVersion) {
         this.version = newVersion;
    }
    
    /**
     * Get the message nonce
     * 
     * @return The nonce
     */
    public String getNonce() {
        return nonce;
    }

    public void setNonce(String newNonce) {
        this.nonce = newNonce;
    }
    
    /**
     * Set a header value
     * 
     * @param key The header key
     * @param value The header value
     */
    public void setHeader(String key, Object value) {
        headers.put(key, value);
    }
    
    /**
     * Get a header value
     * 
     * @param key The header key
     * @return The header value or null if not found
     */
    public Object getHeader(String key) {
        return headers.get(key);
    }
    
    /**
     * Get a header value as string
     * 
     * @param key The header key
     * @return The header value as string or null if not found
     */
    public String getHeaderAsString(String key) {
        Object value = headers.get(key);
        return value != null ? value.toString() : null;
    }
    
    /**
     * Get a header value as integer
     * 
     * @param key The header key
     * @param defaultValue The default value if header not found or not an integer
     * @return The header value as integer or defaultValue
     */
    public int getHeaderAsInt(String key, int defaultValue) {
        Object value = headers.get(key);
        if (value == null) {
            return defaultValue;
        }
        
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        
        try {
            return Integer.parseInt(value.toString());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
    
    /**
     * Set a payload item with proper String conversion for complex objects
     */
    public void setPayload(String key, Object value) {
        if (payload == null) {
            payload = new HashMap<>();
        }
        
        // Ensure proper string conversion for complex objects
        if (value != null && !(value instanceof String) && 
            !(value instanceof Number) && 
            !(value instanceof Boolean) &&
            !(value instanceof JSONObject) && 
            !(value instanceof JSONArray)) {
            // Convert complex objects to strings
            payload.put(key, value.toString());
        } else {
            payload.put(key, value);
        }
    }
    
    /**
     * Get a payload value
     * 
     * @param key The payload key
     * @return The payload value or null if not found
     */
    public Object getPayload(String key) {
        return payload.get(key);
    }
    
    /**
     * Get a payload value as string
     * 
     * @param key The payload key
     * @return The payload value as string or null if not found
     */
    public String getPayloadAsString(String key) {
        Object value = payload.get(key);
        return value != null ? value.toString() : null;
    }
    
    /**
     * Get a payload value as integer
     * 
     * @param key The payload key
     * @param defaultValue The default value if payload not found or not an integer
     * @return The payload value as integer or defaultValue
     */
    public int getPayloadAsInt(String key, int defaultValue) {
        Object value = payload.get(key);
        if (value == null) {
            return defaultValue;
        }
        
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        
        try {
            return Integer.parseInt(value.toString());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
    
    /**
     * Set the message signature
     * 
     * @param signature The Base64 encoded signature
     */
    public void setSignature(String signature) {
        this.signature = signature;
    }
    
    /**
     * Get the message signature
     * 
     * @return The Base64 encoded signature
     */
    public String getSignature() {
        return signature;
    }
    
    /**
     * Get the message content for signing (without the signature field)
     * 
     * @return The message content for signing
     */
    public String getContentForSigning() {
        JSONObject obj = new JSONObject();
        obj.put("type", type);
        obj.put("version", version);
        obj.put("nonce", nonce);
        
        JSONObject headersObj = new JSONObject();
        for (Map.Entry<String, Object> entry : headers.entrySet()) {
            headersObj.put(entry.getKey(), entry.getValue());
        }
        obj.put("headers", headersObj);
        
        JSONObject payloadObj = new JSONObject();
        for (Map.Entry<String, Object> entry : payload.entrySet()) {
            payloadObj.put(entry.getKey(), entry.getValue());
        }
        obj.put("payload", payloadObj);
        
        return obj.toJSON();
    }
    
    /**
     * Generate a random nonce
     * 
     * @return Base64 encoded nonce
     */
    private String generateNonce() {
        byte[] nonceBytes = new byte[Constants.NONCE_SIZE];
        new SecureRandom().nextBytes(nonceBytes);
        return Base64.getEncoder().encodeToString(nonceBytes);
    }
    
    /**
     * Create a simple error message
     * 
     * @param errorCode The error code
     * @param errorMessage The error message
     * @return Error message
     */
    public static Message createErrorMessage(int errorCode, String errorMessage) {
        Message message = new Message(Constants.MSG_TYPE_ERROR);
        message.setPayload("code", errorCode);
        message.setPayload("message", errorMessage);
        return message;
    }
    
    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        obj.put("type", type);
        obj.put("version", version);
        obj.put("nonce", nonce);
        
        if (signature != null) {
            obj.put("signature", signature);
        }
        
        JSONObject headersObj = new JSONObject();
        for (Map.Entry<String, Object> entry : headers.entrySet()) {
            headersObj.put(entry.getKey(), entry.getValue());
        }
        obj.put("headers", headersObj);
        
        JSONObject payloadObj = new JSONObject();
        for (Map.Entry<String, Object> entry : payload.entrySet()) {
            payloadObj.put(entry.getKey(), entry.getValue());
        }
        obj.put("payload", payloadObj);
        
        return obj;
    }
    
    @Override
    public void deserialize(JSONType obj) {
        if (obj instanceof JSONObject) {
            JSONObject jsonObj = (JSONObject) obj;
            
            try {
                this.type = jsonObj.getString("type");
                this.version = jsonObj.getString("version");
                this.nonce = jsonObj.getString("nonce");
                this.signature = jsonObj.getString("signature");
                
                this.headers = new HashMap<>();
                JSONObject headersObj = jsonObj.getObject("headers");
                if (headersObj != null) {
                    for (Object key : headersObj.keySet()) {
                        if (key != null) {
                            Object value = headersObj.get(key);
                            if (value != null) {
                                headers.put((String) key, value);
                            } else {
                                System.err.println("Warning: Null value for header key: " + key);
                            }
                        } else {
                            System.err.println("Warning: Null key in headers object");
                        }
                    }
                }
                
                this.payload = new HashMap<>();
                JSONObject payloadObj = jsonObj.getObject("payload");
                if (payloadObj != null) {
                    for (Object key : payloadObj.keySet()) {
                        if (key != null) {
                            Object value = payloadObj.get(key);
                            if (value != null) {
                                payload.put((String) key, value);
                            } else {
                                System.err.println("Warning: Null value for payload key: " + key);
                            }
                        } else {
                            System.err.println("Warning: Null key in payload object");
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("Error in Message.deserialize: " + e.getMessage());
                e.printStackTrace();
                
                // Ensure we have at least the basic fields initialized
                if (this.type == null) this.type = "UNKNOWN";
                if (this.version == null) this.version = "1.0";
                if (this.nonce == null) this.nonce = "AAAA";
                if (this.headers == null) this.headers = new HashMap<>();
                if (this.payload == null) this.payload = new HashMap<>();
            }
        }
    }

    /**
     * Get all keys in the payload
     * 
     * @return Set of payload keys
     */
    public Set<String> getPayloadKeys() {
        return payload != null ? payload.keySet() : new HashSet<>();
    }
    
    /**
     * Get all payload values as a map
     * 
     * @return Map of all payload values
     */
    public Map<String, Object> getAllPayload() {
        return payload != null ? new HashMap<>(payload) : new HashMap<>();
    }
    
    /**
     * Get a debug string representation of all payload values
     * 
     * @return Debug string
     */
    public String getPayloadDebugString() {
        if (payload == null || payload.isEmpty()) {
            return "Empty payload";
        }
        
        StringBuilder sb = new StringBuilder("Payload contents:\n");
        for (Map.Entry<String, Object> entry : payload.entrySet()) {
            Object value = entry.getValue();
            String valueType = value != null ? value.getClass().getSimpleName() : "null";
            String valueStr = value != null ? (
                value instanceof String ? 
                    "String[" + ((String)value).length() + "]" : 
                    value.toString()
            ) : "null";
            
            sb.append("  ").append(entry.getKey()).append(" (").append(valueType).append("): ")
              .append(valueStr).append("\n");
        }
        return sb.toString();
    }
    
    /**
     * Deserialize message directly from a JSON string with fallback to regex parsing
     * 
     * @param jsonStr The JSON string to deserialize
     * @throws Exception If deserialization fails
     */
    public void deserialize(String jsonStr) throws Exception {
        // Try using JsonIO directly
        try {
            JSONObject jsonObj = merrimackutil.json.JsonIO.readObject(jsonStr);
            deserialize(jsonObj);
            return;
        } catch (Exception e) {
            // Continue to manual parsing if JsonIO fails
        }
        
        // Initialize fields
        this.headers = new HashMap<>();
        this.payload = new HashMap<>();
        
        // Simple manual parser for critical fields
        try {
            // Extract type, version, nonce, and payload using regex
            if (jsonStr.contains("\"type\"")) {
                this.type = extractStringValue(jsonStr, "\"type\"");
            }
            
            if (jsonStr.contains("\"version\"")) {
                this.version = extractStringValue(jsonStr, "\"version\"");
            }
            
            if (jsonStr.contains("\"nonce\"")) {
                this.nonce = extractStringValue(jsonStr, "\"nonce\"");
            }
            
            if (jsonStr.contains("\"signature\"")) {
                this.signature = extractStringValue(jsonStr, "\"signature\"");
            }
            
            // Parse headers and payload sections
            parseSection(jsonStr, "headers", this.headers);
            parseSection(jsonStr, "payload", this.payload);
            
        } catch (Exception e) {
            throw new Exception("Failed to manually parse JSON: " + e.getMessage());
        }
    }
    
    /**
     * Extract a string value from JSON text using regex
     * 
     * @param jsonStr The JSON string
     * @param key The key to extract value for
     * @return The extracted string value
     */
    private String extractStringValue(String jsonStr, String key) {
        String pattern = key + "\\s*:\\s*\"([^\"]+)\"";
        java.util.regex.Pattern r = java.util.regex.Pattern.compile(pattern);
        java.util.regex.Matcher m = r.matcher(jsonStr);
        
        if (m.find()) {
            return m.group(1);
        }
        return null;
    }
    
    /**
     * Parse a section of the JSON (headers or payload) and populate the map
     * 
     * @param jsonStr The JSON string
     * @param sectionName The section name (headers or payload)
     * @param targetMap The map to populate
     */
    private void parseSection(String jsonStr, String sectionName, Map<String, Object> targetMap) {
        // Find the section boundaries
        int startIdx = jsonStr.indexOf("\"" + sectionName + "\"");
        if (startIdx == -1) return;
        
        // Find the opening brace
        startIdx = jsonStr.indexOf("{", startIdx);
        if (startIdx == -1) return;
        
        // Find the closing brace (accounting for nested objects)
        int endIdx = startIdx + 1;
        int braceCount = 1;
        
        while (braceCount > 0 && endIdx < jsonStr.length()) {
            char c = jsonStr.charAt(endIdx);
            if (c == '{') braceCount++;
            else if (c == '}') braceCount--;
            endIdx++;
        }
        
        if (braceCount != 0) return; // Unmatched braces
        
        // Extract the section content
        String sectionJson = jsonStr.substring(startIdx, endIdx);
        
        // Extract key-value pairs using regex
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\"([^\"]+)\"\\s*:\\s*(\"[^\"]*\"|\\d+|true|false|\\{[^}]*\\}|\\[[^\\]]*\\])");
        java.util.regex.Matcher matcher = pattern.matcher(sectionJson);
        
        while (matcher.find()) {
            String key = matcher.group(1);
            String valueStr = matcher.group(2);
            
            // Parse the value based on its type
            Object value;
            if (valueStr.startsWith("\"") && valueStr.endsWith("\"")) {
                // String value
                value = valueStr.substring(1, valueStr.length() - 1);
            } else if (valueStr.equals("true")) {
                value = Boolean.TRUE;
            } else if (valueStr.equals("false")) {
                value = Boolean.FALSE;
            } else if (valueStr.matches("\\d+")) {
                // Integer value
                try {
                    value = Integer.parseInt(valueStr);
                } catch (NumberFormatException e) {
                    value = valueStr; // Keep as string if parsing fails
                }
            } else {
                // Keep complex objects as strings for now
                value = valueStr;
            }
            
            targetMap.put(key, value);
        }
    }

    /**
     * Serialize message to JSON with proper handling of all object types
     */
    // In Message class
    //@Override
// public String serialize() {
//     // Use merrimackutil.json's own serialization
//     return toJSONType().toJSON();
// }

   

    @Override
    public String serialize() {
        JSONObject jsonObj = new JSONObject();
        
        // Add simple fields
        jsonObj.put("type", type);
        jsonObj.put("version", version);
        jsonObj.put("nonce", nonce);
        
        // Create empty headers object - not null
        JSONObject headersObj = new JSONObject();
        if (headers != null) {
            for (Map.Entry<String, Object> entry : headers.entrySet()) {
                Object value = entry.getValue();
                if (value != null) {
                    // Keep original object type if it's a JSON type, otherwise convert to string
                    if (value instanceof JSONObject || value instanceof JSONArray ||
                        value instanceof Number || value instanceof Boolean) {
                        headersObj.put(entry.getKey(), value);
                    } else {
                        headersObj.put(entry.getKey(), value.toString());
                    }
                }
            }
        }
        jsonObj.put("headers", headersObj);
        
        // Create payload object with proper conversion
        JSONObject payloadObj = new JSONObject();
        if (payload != null) {
            for (Map.Entry<String, Object> entry : payload.entrySet()) {
                Object value = entry.getValue();
                if (value != null) {
                    // Keep original object type if it's a JSON type, otherwise convert to string
                    if (value instanceof JSONObject || value instanceof JSONArray ||
                        value instanceof Number || value instanceof Boolean) {
                        payloadObj.put(entry.getKey(), value);
                    } else {
                        payloadObj.put(entry.getKey(), value.toString());
                    }
                }
            }
        }
        jsonObj.put("payload", payloadObj);
        
        return jsonObj.toJSON();
    }

}