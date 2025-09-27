// server.cpp (raw-socket upgrade only; no extra functionality)
#include <openssl/sha.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "lib/base64.hpp"

// Globally Unique Identifier
const std::string GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

std::string sha1(const std::string& input) {
    unsigned char hash[SHA_DIGEST_LENGTH];  // 20 bytes
    SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    return std::string(reinterpret_cast<char*>(hash), SHA_DIGEST_LENGTH);
}

static bool send_all(int fd, const void* data, size_t len) {
    const char* p = static_cast<const char*>(data);
    while (len) {
        ssize_t n = ::send(fd, p, len, 0);
        if (n <= 0) return false;
        p += n; len -= static_cast<size_t>(n);
    }
    return true;
}

static std::string recv_until_double_crlf(int fd) {
    std::string buf;
    char tmp[1024];
    while (buf.find("\r\n\r\n") == std::string::npos) {
        ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0) break;
        buf.append(tmp, tmp + n);
    }
    return buf;
}

static std::string header_value(const std::string& req, const std::string& name) {
    std::string key = name + ":";
    auto pos = req.find(key);
    if (pos == std::string::npos) return {};
    pos += key.size();
    while (pos < req.size() && (req[pos] == ' ' || req[pos] == '\t')) ++pos;
    auto end = req.find("\r\n", pos);
    if (end == std::string::npos) return {};
    return req.substr(pos, end - pos);
}

int main() {
    int server_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // listen on 0.0.0.0
    addr.sin_port = htons(8080);

    if (::bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("bind"); ::close(server_fd); return 1;
    }
    if (::listen(server_fd, 8) < 0) {
        perror("listen"); ::close(server_fd); return 1;
    }

    std::cout << "Server is running on http://localhost:8080" << std::endl;

    while (true) {
        int client_fd = ::accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) { perror("accept"); continue; }

        std::string req = recv_until_double_crlf(client_fd);
        if (req.empty()) { ::close(client_fd); continue; }

        std::cout << "GET /chat HTTP/1.1" << std::endl;
        std::cout << "Host: " << header_value(req, "Host") << std::endl;
        std::cout << "Upgrade: " << header_value(req, "Upgrade") << std::endl;
        std::cout << "Connection: " << header_value(req, "Connection") << std::endl;
        std::cout << "Sec-WebSocket-Key: " << header_value(req, "Sec-WebSocket-Key") << std::endl;

        std::string wsKey = header_value(req, "Sec-WebSocket-Key");
        std::string wsAccept = sha1(wsKey + GUID);
        std::string wsAcceptBase64 = base64::to_base64(wsAccept);

        std::ostringstream resp;
        resp << "HTTP/1.1 101 Switching Protocols\r\n"
             << "Upgrade: websocket\r\n"
             << "Connection: Upgrade\r\n"
             << "Sec-WebSocket-Accept: " << wsAcceptBase64 << "\r\n"
             << "\r\n";

        send_all(client_fd, resp.str().c_str(), resp.str().size());

        uint8_t frame_header[2];
        ::recv(client_fd, frame_header, 2, 0);
        std::cout << "Frame header: " << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(frame_header[0]) << " " << static_cast<int>(frame_header[1]) << std::endl;

        uint64_t payload_length = frame_header[1] & 0x7F;
        std::cout << "Payload length (hex): " << payload_length << std::endl;

        uint8_t masking_key[4];
        ::recv(client_fd, masking_key, 4, 0);
        std::cout << "Masking key: " << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(masking_key[0]) << " " << static_cast<int>(masking_key[1]) << " " << static_cast<int>(masking_key[2]) << " " << static_cast<int>(masking_key[3]) << std::endl;

        std::vector<uint8_t> payload(payload_length);
        ::recv(client_fd, payload.data(), payload_length, 0);

        // Unmask payload
        for (size_t i = 0; i < payload_length; i++) {
            payload[i] ^= masking_key[i % 4];
        }

        std::cout << "Payload: " << std::string(payload.begin(), payload.end()) << std::endl;

        ::close(client_fd);
    }

    ::close(server_fd);
    return 0;
}
