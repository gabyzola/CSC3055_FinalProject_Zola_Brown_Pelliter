package common;

import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;

/**
 * Wrapper for merrimackutil JSON parser to handle parsing quirks
 */
public class JsonParser {
    
    /**
     * Parse JSON string to JSONObject, with fallback to manual parsing
     * 
     * @param jsonString The JSON string to parse
     * @return Parsed JSONObject or null if parsing fails
     */
    public static JSONObject parseObject(String jsonString) {
        // Check if the input is potentially malformed with "}," pattern
        String cleanedJson = jsonString;
        
        // Fix common formatting issues seen in the server responses
        if (jsonString.contains("},\"payload\":")) {
            // Fix malformed headers objects that look like: {"headers":},"payload":...
            cleanedJson = jsonString.replace("},\"payload\":", "\"},\"payload\":");
        }
        
        if (jsonString.contains("\"headers\":},")) {
            // Fix empty headers that are malformed
            cleanedJson = jsonString.replace("\"headers\":},", "\"headers\":{},");
        }
        
        try {
            // First try using the built-in parser with cleaned JSON
            return JsonIO.readObject(cleanedJson);
        } catch (Exception e) {
            try {
                // If the cleaned JSON fails, try the original as is
                if (!cleanedJson.equals(jsonString)) {
                    return JsonIO.readObject(jsonString);
                }
            } catch (Exception ignored) {
                // Continue to manual parsing
            }
            
            System.out.println("Warning: Standard parser failed, trying fallback method");
            return parseObjectManually(cleanedJson);
        }
    }

    /**
     * Manual JSON parser for simple objects
     * 
     * @param jsonString The JSON string to parse
     * @return Manually constructed JSONObject or null if parsing fails
     */
    private static JSONObject parseObjectManually(String jsonString) {
        try {
            // Create an empty object
            JSONObject object = new JSONObject();
            
            // Extract type, version, nonce fields
            String type = extractField(jsonString, "type");
            String version = extractField(jsonString, "version");
            String nonce = extractField(jsonString, "nonce");
            
            if (type != null) object.put("type", type);
            if (version != null) object.put("version", version);
            if (nonce != null) object.put("nonce", nonce);
            
            // Extract payload object
            String payloadJson = extractObject(jsonString, "payload");
            if (payloadJson != null) {
                JSONObject payload = new JSONObject();
                
                // Handle clientId
                String clientId = extractField(payloadJson, "clientId");
                if (clientId != null) payload.put("clientId", clientId);
                
                // Handle publicKey
                String publicKey = extractField(payloadJson, "publicKey");
                if (publicKey != null) payload.put("publicKey", publicKey);
                
                // Handle sessionId in payload - NEW
                String sessionId = extractField(payloadJson, "sessionId");
                if (sessionId != null) payload.put("sessionId", sessionId);
                
                // Handle status in payload - NEW
                String status = extractField(payloadJson, "status");
                if (status != null) payload.put("status", status);
                
                // Handle error code and message - NEW
                String code = extractField(payloadJson, "code");
                if (code != null) {
                    try {
                        payload.put("code", Integer.parseInt(code));
                    } catch (NumberFormatException e) {
                        payload.put("code", code);
                    }
                }
                
                String message = extractField(payloadJson, "message");
                if (message != null) payload.put("message", message);
                
                object.put("payload", payload);
            }
            
            // Extract headers object
            String headersJson = extractObject(jsonString, "headers");
            JSONObject headers = new JSONObject();
            if (headersJson != null) {
                // Extract sessionId from headers
                String sessionId = extractField(headersJson, "sessionId");
                if (sessionId != null) headers.put("sessionId", sessionId);
            }
            object.put("headers", headers);
            
            return object;
        } catch (Exception e) {
            System.err.println("Manual JSON parsing failed: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Extract a field value from JSON string
     */
    private static String extractField(String json, String fieldName) {
        // Try to extract string value first (with quotes)
        String stringPattern = "\"" + fieldName + "\":\"";
        int strStart = json.indexOf(stringPattern);
        
        if (strStart != -1) {
            strStart += stringPattern.length();
            int strEnd = json.indexOf("\"", strStart);
            
            if (strEnd != -1) {
                return json.substring(strStart, strEnd);
            }
        }
        
        // If not a string, try to extract numeric value (without quotes)
        String numPattern = "\"" + fieldName + "\":";
        int numStart = json.indexOf(numPattern);
        
        if (numStart != -1) {
            numStart += numPattern.length();
            
            // Skip any whitespace
            while (numStart < json.length() && Character.isWhitespace(json.charAt(numStart))) {
                numStart++;
            }
            
            // If the first character is a digit, extract the number
            if (numStart < json.length() && (Character.isDigit(json.charAt(numStart)) || 
                                           json.charAt(numStart) == '-' || 
                                           json.charAt(numStart) == '+')) {
                int numEnd = numStart;
                
                // Find the end of the number
                while (numEnd < json.length() && 
                       (Character.isDigit(json.charAt(numEnd)) || 
                        json.charAt(numEnd) == '.' || 
                        json.charAt(numEnd) == 'e' || 
                        json.charAt(numEnd) == 'E' ||
                        json.charAt(numEnd) == '-' ||
                        json.charAt(numEnd) == '+')) {
                    numEnd++;
                }
                
                if (numEnd > numStart) {
                    return json.substring(numStart, numEnd);
                }
            }
            
            // Check for boolean values
            if (numStart + 4 <= json.length() && json.substring(numStart, numStart + 4).equals("true")) {
                return "true";
            }
            if (numStart + 5 <= json.length() && json.substring(numStart, numStart + 5).equals("false")) {
                return "false";
            }
            if (numStart + 4 <= json.length() && json.substring(numStart, numStart + 4).equals("null")) {
                return null;
            }
        }
        
        return null;
    }
    
    /**
     * Extract a JSON object from a JSON string
     */
    private static String extractObject(String json, String objectName) {
        String pattern = "\"" + objectName + "\":{";
        int start = json.indexOf(pattern);
        
        if (start == -1) return null;
        
        start += pattern.length() - 1; // Include the opening brace
        
        // Count braces to find matching closing brace
        int braceCount = 1;
        int end = start + 1;
        
        while (braceCount > 0 && end < json.length()) {
            char c = json.charAt(end);
            if (c == '{') braceCount++;
            else if (c == '}') braceCount--;
            end++;
        }
        
        if (braceCount != 0) return null;
        
        return json.substring(start, end);
    }
    
    /**
     * Convert a Message object to JSON string manually
     * 
     * @param message The Message to serialize
     * @return JSON string representation of the message
     */
    public static String serializeMessage(Message message) {
        if (message == null) {
            return "{}";
        }
        
        try {
            // Instead of manual serialization, use Message's built-in serialize method
            // which now handles complex objects correctly
            return message.serialize();
        } catch (Exception e) {
            System.err.println("Error in serializeMessage: " + e.getMessage());
            
            // Create a minimal valid JSON object as fallback
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            sb.append("\"type\":\"").append(message.getType() != null ? message.getType() : "UNKNOWN").append("\",");
            sb.append("\"version\":\"").append(message.getVersion() != null ? message.getVersion() : "1.0").append("\",");
            sb.append("\"nonce\":\"").append(message.getNonce() != null ? message.getNonce() : "AAAA").append("\",");
            sb.append("\"headers\":{},");
            sb.append("\"payload\":{}");
            sb.append("}");
            
            return sb.toString();
        }
    }
}