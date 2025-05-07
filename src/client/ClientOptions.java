package client;

import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.util.Tuple;

/**
 * Parses and manages command-line options for the client application.
 */
public class ClientOptions {
    // Command flags
    private boolean register = false;
    private boolean upload = false;
    private boolean download = false;
    private boolean list = false;
    private boolean verify = false;
    private boolean blockchain = false;
    private boolean help = false;
    private boolean userOnly = false;
    
    // Option values
    private String username = null;
    private String host = null;
    private int port = 0;
    private String filePath = null;
    private String fileHash = null;
    private String destinationDir = null;
    private String configPath = null;
    
    /**
     * Parse command line options
     * 
     * @param args Command line arguments
     * @return true if parsing was successful
     */
    public boolean parseOptions(String[] args) {
        OptionParser parser = new OptionParser(args);
        
        // Define long options
        LongOption[] longOpts = {
            new LongOption("register", false, 'r'),
            new LongOption("upload", true, 'u'),
            new LongOption("download", true, 'd'),
            new LongOption("list", false, 'l'),
            new LongOption("verify", true, 'v'),
            new LongOption("blockchain", false, 'b'),
            new LongOption("help", false, 'h'),
            new LongOption("user", true, 's'),
            new LongOption("host", true, 'o'),
            new LongOption("port", true, 'p'),
            new LongOption("dest", true, 't'),
            new LongOption("config", true, 'c'),
            new LongOption("user-only", false, 'y')
        };
        
        parser.setLongOpts(longOpts);
        
        // Parse options
        Tuple<Character, String> opt;
        while ((opt = parser.getLongOpt(false)) != null) {
            switch (opt.getFirst()) {
                case 'r':
                    register = true;
                    break;
                case 'u':
                    upload = true;
                    filePath = opt.getSecond();
                    break;
                case 'd':
                    download = true;
                    fileHash = opt.getSecond();
                    break;
                case 'l':
                    list = true;
                    break;
                case 'v':
                    verify = true;
                    fileHash = opt.getSecond();
                    break;
                case 'b':
                    blockchain = true;
                    break;
                case 'h':
                    help = true;
                    return true;
                case 's':
                    username = opt.getSecond();
                    break;
                case 'o':
                    host = opt.getSecond();
                    break;
                case 'p':
                    try {
                        port = Integer.parseInt(opt.getSecond());
                    } catch (NumberFormatException e) {
                        System.err.println("Invalid port number: " + opt.getSecond());
                        return false;
                    }
                    break;
                case 't':
                    destinationDir = opt.getSecond();
                    break;
                case 'c':
                    configPath = opt.getSecond();
                    break;
                case 'y':
                    userOnly = true;
                    break;
                default:
                    System.err.println("Unknown option: " + opt.getFirst());
                    return false;
            }
        }
        
        return true;
    }
    
    /**
     * Print help message
     */
    public void printHelp() {
        System.out.println("usage:");
        System.out.println("client --register --user <username> --host <host> --port <portnum>");
        System.out.println("client --upload <filepath> --user <username> --host <host> --port <portnum>");
        System.out.println("client --download <filehash> --dest <directory> --user <username> --host <host> --port <portnum>");
        System.out.println("client --list --user <username> --host <host> --port <portnum>");
        System.out.println("client --verify <filehash> --user <username> --host <host> --port <portnum>");
        System.out.println("client --blockchain --user <username> --host <host> --port <portnum>");
        System.out.println("options:");
        System.out.println("-r, --register Register a new account");
        System.out.println("-u, --upload Upload a file to the blockchain");
        System.out.println("-d, --download Download a file from the blockchain");
        System.out.println("-l, --list List all available files");
        System.out.println("-v, --verify Verify file integrity on the blockchain");
        System.out.println("-b, --blockchain View blockchain transaction history");
        System.out.println("-usr, --user The username");
        System.out.println("-h, --host The host name of the server");
        System.out.println("-p, --port The port number for the server");
        System.out.println("-dst, --dest Destination directory for downloaded files");
        System.out.println("-y, --user-only Show only files uploaded by the current user");
        System.out.println("-c, --config Custom configuration file path");
        System.out.println("-h, --help Display this help message");
    }
    
    // Getters for all options
    public boolean isRegister() { return register; }
    public boolean isUpload() { return upload; }
    public boolean isDownload() { return download; }
    public boolean isList() { return list; }
    public boolean isVerify() { return verify; }
    public boolean isBlockchain() { return blockchain; }
    public boolean isHelp() { return help; }
    public boolean isUserOnly() { return userOnly; }
    
    public String getUsername() { return username; }
    public String getHost() { return host; }
    public int getPort() { return port; }
    public String getFilePath() { return filePath; }
    public String getFileHash() { return fileHash; }
    public String getDestinationDir() { return destinationDir; }
    public String getConfigPath() { return configPath; }
}