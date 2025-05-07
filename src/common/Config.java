package common;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;

/**
 * Handles loading and accessing configuration from JSON files.
 */
public class Config {
    private JSONObject configData;
    private static Map<String, Config> instances = new HashMap<>();
    
    /**
     * Loads configuration from the specified file path
     * 
     * @param configPath Path to the configuration file
     * @throws IOException If file cannot be read
     */
    private Config(String configPath) throws IOException {
        this.configData = JsonIO.readObject(new File(configPath));
    }
    
    /**
     * Get a shared instance of Config for the specified file
     * 
     * @param configPath Path to the configuration file
     * @return Config instance
     * @throws IOException If file cannot be read
     */
    public static Config getInstance(String configPath) throws IOException {
        if (!instances.containsKey(configPath)) {
            instances.put(configPath, new Config(configPath));
        }
        return instances.get(configPath);
    }
    
    /**
     * Get a shared instance with a default configuration path
     * 
     * @param isServer Whether this is the server config
     * @return Config instance
     * @throws IOException If file cannot be read
     */
    public static Config getInstance(boolean isServer) throws IOException {
        String configPath = isServer ? "config/server-config.json" : "config/client-config.json";
        return getInstance(configPath);
    }
    
    /**
     * Get shared system config instance
     * 
     * @return Config instance
     * @throws IOException If file cannot be read
     */
    public static Config getSystemConfig() throws IOException {
        return getInstance("config/system-config.json");
    }
    
    /**
     * Get a string value from configuration
     * 
     * @param key The configuration key (dot notation for nested properties)
     * @param defaultValue Default value if key not found
     * @return String value from config
     */
    public String getString(String key, String defaultValue) {
        Object value = getValue(key);
        return value != null ? value.toString() : defaultValue;
    }
    
    /**
     * Get an integer value from configuration
     * 
     * @param key The configuration key (dot notation for nested properties)
     * @param defaultValue Default value if key not found
     * @return Integer value from config
     */
    public int getInt(String key, int defaultValue) {
        Object value = getValue(key);
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
     * Get a long value from configuration
     * 
     * @param key The configuration key (dot notation for nested properties)
     * @param defaultValue Default value if key not found
     * @return Long value from config
     */
    public long getLong(String key, long defaultValue) {
        Object value = getValue(key);
        if (value == null) {
            return defaultValue;
        }
        
        if (value instanceof Number) {
            return ((Number) value).longValue();
        }
        
        try {
            return Long.parseLong(value.toString());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
    
    /**
     * Get a boolean value from configuration
     * 
     * @param key The configuration key (dot notation for nested properties)
     * @param defaultValue Default value if key not found
     * @return Boolean value from config
     */
    public boolean getBoolean(String key, boolean defaultValue) {
        Object value = getValue(key);
        if (value == null) {
            return defaultValue;
        }
        
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        
        return Boolean.parseBoolean(value.toString());
    }
    
    /**
     * Get a nested JSONObject from configuration
     * 
     * @param key The configuration key (dot notation for nested properties)
     * @return JSONObject from config or null if not found
     */
    public JSONObject getObject(String key) {
        Object value = getValue(key);
        return value instanceof JSONObject ? (JSONObject) value : null;
    }
    
    /**
     * Get a value from configuration using dot notation
     * 
     * @param key The configuration key (dot notation for nested properties)
     * @return Object from config or null if not found
     */
    private Object getValue(String key) {
        if (configData == null || key == null || key.isEmpty()) {
            return null;
        }
        
        String[] parts = key.split("\\.");
        Object current = configData;
        
        for (String part : parts) {
            if (current instanceof JSONObject) {
                current = ((JSONObject) current).get(part);
                if (current == null) {
                    return null;
                }
            } else {
                return null;
            }
        }
        
        return current;
    }
    
    /**
     * Validate that the configuration contains required keys
     * 
     * @param requiredKeys Array of required configuration keys
     * @throws IllegalArgumentException If any required key is missing
     */
    public void validate(String[] requiredKeys) throws IllegalArgumentException {
        for (String key : requiredKeys) {
            if (getValue(key) == null) {
                throw new IllegalArgumentException("Missing required configuration key: " + key);
            }
        }
    }
    
    /**
     * Check if a configuration file exists
     * 
     * @param configPath Path to check
     * @return True if file exists
     */
    public static boolean exists(String configPath) {
        return Files.exists(Paths.get(configPath));
    }
}