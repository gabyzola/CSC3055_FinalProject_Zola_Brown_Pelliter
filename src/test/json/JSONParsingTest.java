package test.json;

import java.io.File;
import java.nio.file.Files;
import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;

public class JSONParsingTest {
    public static void main(String[] args) {
        try {
            // Test 1: Direct string parsing
            String simpleJson = "{\"key\":\"value\"}";
            System.out.println("Test 1: Parsing direct string");
            JSONObject obj1 = JsonIO.readObject(simpleJson);
            System.out.println("Success! Result: " + obj1.getString("key"));
            
            // Test 2: File parsing
            File tempFile = File.createTempFile("test", ".json");
            tempFile.deleteOnExit();
            String fileJson = "{\n  \"storage\": {\n    \"test_path\": \"/tmp/test\"\n  }\n}";
            Files.write(tempFile.toPath(), fileJson.getBytes());
            
            System.out.println("Test 2: Parsing from file: " + tempFile.getAbsolutePath());
            JSONObject obj2 = JsonIO.readObject(new File(tempFile.getAbsolutePath()));
            System.out.println("Success! Result: " + obj2.getObject("storage").getString("test_path"));
            
            // Test 3: Config.getInstance method
            System.out.println("Test 3: Testing Config.getInstance with: " + tempFile.getAbsolutePath());
            common.Config config = common.Config.getInstance(tempFile.getAbsolutePath());
            String value = config.getString("storage.test_path", null);
            System.out.println("Success! Config value: " + value);
        } catch (Exception e) {
            System.err.println("Test failed with exception: " + e.getMessage());
            e.printStackTrace();
        }
    }
}