#! /bin/bash

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    rm -f ./client
    exit 0
}

# Set trap to call cleanup on interrupt and exit
trap cleanup SIGINT SIGTERM EXIT

# Compile the server
g++ -std=c++17 -I /opt/homebrew/Cellar/openssl@3/3.5.1/include -L /opt/homebrew/Cellar/openssl@3/3.5.1/lib -l ssl -l crypto client.cpp -o client

# Start the server
./client