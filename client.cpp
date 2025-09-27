#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iomanip>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "lib/base64.hpp"
#include <openssl/sha.h>

// Globally Unique Identifier
const std::string GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

int connect_tcp(const char* host, int port) {
    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return -1; }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        perror("inet_pton"); ::close(sock); return -1;
    }
    if (::connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect"); ::close(sock); return -1;
    }
    return sock;
}

bool send_all(int sock, const void* data, size_t len) {
    const char* p = static_cast<const char*>(data);
    while (len) {
        ssize_t n = ::send(sock, p, len, 0);
        if (n <= 0) return false;
        p += n; len -= (size_t)n;
    }
    return true;
}

std::string recv_until_double_crlf(int sock) {
    std::string buf;
    char tmp[1024];
    while (buf.find("\r\n\r\n") == std::string::npos) {
        ssize_t n = ::recv(sock, tmp, sizeof(tmp), 0);
        if (n <= 0) break;
        buf.append(tmp, tmp + n);
    }
    return buf;
}

std::string generateWebSocketKey() {
    unsigned char nonce[16];
    for (auto& b : nonce) {
        b = rand() % 256;
    }
    return base64::to_base64(std::string_view(reinterpret_cast<const char*>(nonce), sizeof(nonce)));
}

std::string sha1(const std::string& input) {
    unsigned char hash[SHA_DIGEST_LENGTH];  // SHA_DIGEST_LENGTH = 20 bytes
    SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);

    return std::string(reinterpret_cast<char*>(hash), SHA_DIGEST_LENGTH);
}

std::vector<uint8_t> generateMaskingKey() {
    std::vector<uint8_t> maskingKey;
    
    for (int i = 0; i < 4; i++) {
        maskingKey.push_back(rand() % 256);
    }

    return maskingKey;
    // return {0x37, 0xfa, 0x21, 0x3d};
}

std::vector<uint8_t> buildFrame(const std::string& message) {
    std::vector<uint8_t> frame;
    frame.push_back(0x81); // FIN=1, RSV1-3=0, opcode=0x1 (text) -> 1000 0001
    frame.push_back(0x80 | (message.size() & 0x7F)); // MASK=1, payload len (0-125)
    const std::vector<uint8_t> maskingKey = generateMaskingKey();
    frame.insert(frame.end(), maskingKey.begin(), maskingKey.end());
    for (size_t i = 0; i < message.size(); i++) {
        frame.push_back(message[i] ^ maskingKey[i % 4]);
    }
    return frame;
}

std::string get_header_value(const std::string& resp, const std::string& name) {
    std::string key = name + ":";
    auto pos = resp.find(key);
    if (pos == std::string::npos) return {};
    pos += key.size();
    // skip spaces
    while (pos < resp.size() && (resp[pos] == ' ' || resp[pos] == '\t')) ++pos;
    auto end = resp.find("\r\n", pos);
    if (end == std::string::npos) return {};
    return resp.substr(pos, end - pos);
}

int main() {
    int sock = connect_tcp("127.0.0.1", 8080);
    if (sock < 0) return 1;

    std::string wsKey = generateWebSocketKey();
    std::ostringstream req;
    req << "GET /chat HTTP/1.1\r\n"
        << "Host: 127.0.0.1:8080\r\n"
        << "Upgrade: websocket\r\n"
        << "Connection: Upgrade\r\n"
        << "Sec-WebSocket-Version: 13\r\n"
        << "Sec-WebSocket-Key: " << wsKey << "\r\n\r\n";

    send_all(sock, req.str().c_str(), req.str().size());
    std::string resp = recv_until_double_crlf(sock);
    std::cout << "--- Handshake response ---\n" << resp << "\n";

    bool status101 = resp.find("101 Switching Protocols") != std::string::npos;
    std::string upgrade = get_header_value(resp, "Upgrade");
    std::string connection = get_header_value(resp, "Connection");
    std::string accept = get_header_value(resp, "Sec-WebSocket-Accept");

    std::string expect_accept = base64::to_base64(sha1(wsKey + GUID));

    std::cout << "Upgrade: " << upgrade << "\n";
    std::cout << "Connection: " << connection << "\n";
    std::cout << "Sec-WebSocket-Accept: " << accept << "\n";

    if (!status101 || expect_accept != accept) {
        std::cerr << "Handshake verification FAILED" << std::endl;
        ::close(sock);
        return 1;
    } else {
        std::cout << "Handshake verification OK" << std::endl;
    }

    auto frame = buildFrame("Hello, World!");
    std::cout << "Frame bytes: ";
    for (unsigned char c : frame) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c << " ";
    }
    std::cout << std::dec << std::endl;
    send_all(sock, frame.data(), frame.size());
    std::cout << "Frame sent (" << frame.size() << " bytes)" << std::endl;

    ::close(sock);

    return 0;
}