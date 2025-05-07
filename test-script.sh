#!/bin/bash
# test-script.sh for running from project root

# Define the correct paths to your config files
SERVER_CONFIG="config/server_config.json"
CLIENT_CONFIG="config/client_config.json"
TEST_FILE="test-files/sample.txt"

echo "======= Testing Client-Server Communication ======="
pkill -f "java -jar dist/server.jar" || true
sleep 2
# Start server in background
java -jar dist/server.jar $SERVER_CONFIG &
SERVER_PID=$!
sleep 2  # Give server time to start

# Run client commands
echo "Testing file upload..."
java -jar dist/client.jar --config $CLIENT_CONFIG --upload $TEST_FILE

echo "Testing file download..."
java -jar dist/client.jar --config $CLIENT_CONFIG --download sample.txt

echo "Testing blockchain query..."
java -jar dist/client.jar --config $CLIENT_CONFIG --list

# Cleanup
kill $SERVER_PID