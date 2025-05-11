# Post-Quantum Blockchain File Sharing System
A secure file sharing system using post-quantum cryptography algorithms (CRYSTALS-Kyber and CRYSTALS-Dilithium) with blockchain-based transaction ledger.

## Team
Gaby Zola : client 
Jack Pelitier : blockchain
Mike Brown : common : pqcrypto

## Features

* Post-quantum secure key exchange using CRYSTALS-Kyber
* Digital signatures using CRYSTALS-Dilithium
* Two-factor authentication with TOTP
* Blockchain ledger for file transaction history
* File integrity verification
* AES-256-GCM encryption for file contents

## Requirements

* Java 11 or later
* Sufficient disk space for file storage
* Google Authenticator or FreeOTP app for 2FA

## Building the Project
Copy the src, lib, and test-files (literally the folder named "test-files" and the txt file in it) into your directory (the rest can stay)

Use the included build.xml to compile the project:
```
ant or ant dist
```
This will create two JAR files in the dist directory:

* server.jar - The server application
* client.jar - The client application

## Usage

### Starting the Server
```
java -jar dist/server.jar
```
Optional arguments:

* `--config <configfile>` - Specify a custom configuration file
* `--help` - Display help message

### Using the Client
The client provides several commands:

Register a new user:
```
java -jar dist/client.jar --register --user <username> --host <host> --port <portnum>
java -jar dist/client.jar --register --user testuser --host localhost --port 5100

TOTP Secrect
* for reference you totp secret can be found in the users.json file after registering labelled "totpSecret", after that its the same process as in project 4 with the freeOTP app (set to SHA1, timeout, paste the base32 string in the bottom input box, add an account name and an optional provider name, scan it with the app on your phone, and type in the code that appears at the time you're trying to authenticate)
```

Upload a file:
```
java -jar dist/client.jar --upload <filepath> --user <username> --host <host> --port <portnum>
java -jar dist/client.jar --upload test-files/sample.txt --user testuser --host localhost --port 5100
```

Download a file:
```
java -jar dist/client.jar --download <filehash> --dest <directory> --user <username> --host <host> --port <portnum>
java -jar dist/client.jar --download iRYmsbEHTJSNItdkD97NKPXAhLjO9c9ziO3vjqtEDuTym1YkYokQ2cNnsfe/bWnoCEdHb3LjLWoJK2mHpDybog== --dest ./downloaded_files --user testuser --host localhost --port 5100
```

List available files:
```
java -jar dist/client.jar --list --user <username> --host <host> --port <portnum>
java -jar dist/client.jar --list --user testuser --host localhost --port 5100
```

Verify file integrity:
```
java -jar dist/client.jar --verify <filehash> --user <username> --host <host> --port <portnum>
java -jar dist/client.jar --verify iRYmsbEHTJSNItdkD97NKPXAhLjO9c9ziO3vjqtEDuTym1YkYokQ2cNnsfe/bWnoCEdHb3LjLWoJK2mHpDybog== --user testuser --host localhost --port 5100

```

View blockchain history:
```
java -jar dist/client.jar --blockchain --user <username> --host <host> --port <portnum>
java -jar dist/client.jar --blockchain --user testuser --host localhost --port 5100
```

## Quick Testing
For a complete test of all functionality, you can use the included test script:
```
./test-commands.sh
```
This script will:
1. Start the server
2. Register a test user
3. Upload a sample file
4. List files
5. Verify file integrity
6. Download the file
7. View blockchain history
8. Stop the server

## Configuration
The system uses three configuration files:

* client-config.json - Client configuration
* server-config.json - Server configuration
* system-config.json - Shared system parameters

## For Testing Purposes Only
This system is set up with some simplifications for testing:
- Fixed TOTP code "123456" is accepted
- Password requirements are relaxed
- Auto-registration of users is enabled