#!/bin/bash
# Test script for PQ Blockchain File Sharing System

# Set variables
USER_NAME="testuser"
HOST="localhost"
PORT="5100"
TEST_FILE="test-files/sample.txt"
DOWNLOAD_DIR="downloads"
TEST_PASSWORD="testPassword12345"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Create necessary directories
mkdir -p "$DOWNLOAD_DIR"
mkdir -p "test-files"

# Create test file if it doesn't exist
if [ ! -f "$TEST_FILE" ]; then
    echo "Creating test file..."
    echo "This is a test file for PQ Blockchain File Sharing System" > "$TEST_FILE"
    echo "Added random content at $(date)" >> "$TEST_FILE"
    echo "File size: $(wc -c < "$TEST_FILE") bytes" >> "$TEST_FILE"
fi

# Start the server in background
echo -e "${YELLOW}Starting server...${NC}"
java -jar dist/server.jar &
SERVER_PID=$!

# Wait for server to start
sleep 2
echo -e "${GREEN}Server started with PID $SERVER_PID${NC}"

# Clean up function
cleanup() {
    echo -e "${YELLOW}Stopping server...${NC}"
    kill $SERVER_PID
    echo -e "${GREEN}Server stopped${NC}"
    exit 0
}

# Set trap for cleanup
trap cleanup EXIT INT TERM

# Register a new user
echo -e "\n${YELLOW}Testing registration...${NC}"
java -jar dist/client.jar --register --user "$USER_NAME" --host "$HOST" --port "$PORT"

# List files (should be empty initially)
echo -e "\n${YELLOW}Testing list files...${NC}"
java -jar dist/client.jar --list --user "$USER_NAME" --host "$HOST" --port "$PORT"

# Upload a file
echo -e "\n${YELLOW}Testing file upload...${NC}"
java -jar dist/client.jar --upload "$TEST_FILE" --user "$USER_NAME" --host "$HOST" --port "$PORT"

# List files again (should show the uploaded file)
echo -e "\n${YELLOW}Testing list files after upload...${NC}"
java -jar dist/client.jar --list --user "$USER_NAME" --host "$HOST" --port "$PORT"

# Get the file hash from the output (would need parsing in real script)
echo -e "\n${YELLOW}Please enter the file hash from the output above:${NC}"
read FILE_HASH

if [ -n "$FILE_HASH" ]; then
    # Verify file
    echo -e "\n${YELLOW}Testing file verification...${NC}"
    java -jar dist/client.jar --verify "$FILE_HASH" --user "$USER_NAME" --host "$HOST" --port "$PORT"

    # Download file
    echo -e "\n${YELLOW}Testing file download...${NC}"
    java -jar dist/client.jar --download "$FILE_HASH" --dest "$DOWNLOAD_DIR" --user "$USER_NAME" --host "$HOST" --port "$PORT"
fi

# View blockchain
echo -e "\n${YELLOW}Testing blockchain view...${NC}"
java -jar dist/client.jar --blockchain --user "$USER_NAME" --host "$HOST" --port "$PORT"

echo -e "\n${GREEN}All tests completed.${NC}"