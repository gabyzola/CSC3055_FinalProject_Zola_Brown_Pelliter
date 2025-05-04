package common;

import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;

import java.io.File;
import java.io.FileNotFoundException; 
import java.util.HashMap;
import java.util.Map;

import javax.naming.ConfigurationException;

/**
 * centralized access to config parameters from the json files
 * supports nested properties using dot notation
 */
public class Config {
    private JSONObject systemConfig;
    private JSONObject specifiedConfig;

    private final Map<String, Object> valueCache = new HashMap<>();

    /**
     * 
     * @param systemConfigPath
     * @param specifiConfigPath
     * @throws ConfigurationException
     */
    public Config(String systemConfigPath, String specifiConfigPath) throws ConfigException {

        try {
            // load system wide configuration 
            this.systemConfig = JsonIO.readObject(new File(specifiConfigPath));
            System.out.println("Config: loaded system config file from: " + systemConfigPath);

            // load specific config (client or server)
            this.specifiedConfig = JsonIO.readObject(new File(specifiConfigPath));
            System.out.println("Config: loaded specific config file from: " + specifiConfigPath);
        } catch (FileNotFoundException e) {
            throw new ConfigException("Config: ERROR Failed to load configuration: " + e.getMessage(), e);
        }   
    }

    /**
     * 
     * @param path
     * @param defaultValue
     * @return
     */
    public String getString(String path, String defaultValue) {
        // check cache first 
        System.out.println("Checking the cache...");
        if (valueCache.containsKey(path)) {
            System.out.println("Config: value found in the cache");
            Object value = valueCache.get(path);
            System.out.println("Config: value extracted, returning");
            return (value instanceof String) ? (String)value : defaultValue;
        }
        System.out.println("Config: value not found in cache");

        // split the path into parts
        String[] parts = path.split("\\.");

        // try specific confic first, then fall back to system
        System.out.println("Config: trying specific config");
        String value = getNestedString(specifiedConfig, parts);
        if (value == null) {
            System.out.println("Config: couldnt get specific, trying system");
            value = getNestedString(systemConfig, parts);
        }

        // cache the result
        if (value != null) {
            valueCache.put(path, value);
            System.out.println("Config: possible success");
            return value;
        }

        System.out.println("Config: returning default value");
        return defaultValue;
    }

    /**
     * gets an integer value from the configuration
     * @param path
     * @param defaultValue
     * @return
     */
    public int getInt(String path, int defaultValue) {

        System.out.println("Config: checking cache for value");
        // check the cache first 
        if (valueCache.containsKey(path)) {
            System.out.println("Config: value found in cache");
            Object value = valueCache.get(path);
            System.out.println("Config: value extracted");
            return (value instanceof Integer) ? (Integer)value : defaultValue;
        }
        System.out.println("Config: value not found in cache");

        // split path into parts
        String[] parts = path.split("\\.");

        // try specific, fallback to system
        System.out.println("Config: trying specific");
        Integer value = getNestedInt(specifiedConfig, parts);
        if (value == null) {
            System.out.println("Config: specific failed, defaulting to system");
            value = getNestedInt(systemConfig, parts);
        }

        // cache the result
        if (value != null) {
            System.out.println("value holds substance");
            valueCache.put(path, value);
            System.out.println("Config: value cached, returning");
            return value;
        }

        System.out.println("Config: value held no substance, defaulting and returning");

        return defaultValue;

    }

    /**
     * gets an boolean value from the configuration
     * @param path
     * @param defaultValue
     * @return
     */
    public boolean getBoolean(String path, boolean defaultValue) {

        System.out.println("Config: checking cache for value");
        // check the cache first 
        if (valueCache.containsKey(path)) {
            System.out.println("Config: value found in cache");
            Object value = valueCache.get(path);
            System.out.println("Config: value extracted");
            return (value instanceof Boolean) ? (Boolean)value : defaultValue;
        }
        System.out.println("Config: value not found in cache");

        // split path into parts
        String[] parts = path.split("\\.");

        // try specific, fallback to system
        System.out.println("Config: trying specific");
        Boolean value = getNestedBoolean(specifiedConfig, parts);
        if (value == null) {
            System.out.println("Config: specific failed, defaulting to system");
            value = getNestedBoolean(systemConfig, parts);
        }

        // cache the result
        if (value != null) {
            System.out.println("value holds substance");
            valueCache.put(path, value);
            System.out.println("Config: value cached, returning");
            return value;
        }

        System.out.println("Config: value held no substance, defaulting and returning");

        return defaultValue;
    }

    /**
     * gets nested string value from a JSON object
     * @param jsonObj
     * @param parts
     * @return
     */
    private String getNestedString(JSONObject jsonObj, String[] parts) {
        JSONObject current = jsonObj;

        // navigate to the nested object
        System.out.println("Config: Searching...");
        for (int i = 0; i < parts.length - 1; i++) {
            current = current.getObject(parts[i]);
            if (current == null) {
                System.out.println("Config: null found");
                return null;
            }
        }

        // get final value
        System.out.println("Config: a value was found, returning");
        return current.getString(parts[parts.length - 1]);
    }

    /**
     * gets nested integer value from a JSON object
     * @param jsonObj
     * @param parts
     * @return
     */
    private Integer getNestedInt(JSONObject jsonObj, String[] parts) {
        JSONObject current = jsonObj;

        // navigate to the nested object
        System.out.println("Config: Searching...");
        for (int i = 0; i < parts.length - 1; i++) {
            current = current.getObject(parts[i]);
            if (current == null) {
                System.out.println("Config: null found");
                return null;
            }
        }

        // get final value
        System.out.println("Config: a value was found, returning");
        return current.getInt(parts[parts.length - 1]);
    }

    /**
     * gets nested string value from a JSON object
     * @param jsonObj
     * @param parts
     * @return
     */
    private Boolean getNestedBoolean(JSONObject jsonObj, String[] parts) {
        JSONObject current = jsonObj;

        // navigate to the nested object
        System.out.println("Config: Searching...");
        for (int i = 0; i < parts.length - 1; i++) {
            current = current.getObject(parts[i]);
            if (current == null) {
                System.out.println("Config: null found");
                return null;
            }
        }

        System.out.println("Config: a value was found, returning");
        // get final value
        return current.getBoolean(parts[parts.length - 1]);
    }

    /**
     * gets the raw JSONObject for more complex operations
     * @param isSystemConfig
     * @return systemConfig if boolean is true (we're dealing with a system config), specifiedConfig otherwise (dealing with a specific config)
     */
    public JSONObject getRawConfig(boolean isSystemConfig) {
        return isSystemConfig ? systemConfig : specifiedConfig;
    }

}
