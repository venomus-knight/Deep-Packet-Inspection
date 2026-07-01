#include "dashboard_server.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <functional>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

// For WebSocket SHA-1 + Base64
#include <array>
#include <iomanip>

namespace DPI {

DashboardServer::DashboardServer(int port) : port_(port) {}

DashboardServer::~DashboardServer() { stop(); }

void DashboardServer::setStatsProvider(StatsProvider provider) {
  stats_provider_ = std::move(provider);
}

bool DashboardServer::start() {
  server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd_ < 0) {
    std::cerr << "[Dashboard] Socket creation failed: " << strerror(errno)
              << "\n";
    return false;
  }

  int opt = 1;
  setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr;
  std::memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port_);

  if (bind(server_fd_, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    std::cerr << "[Dashboard] Bind failed on port " << port_ << ": "
              << strerror(errno) << "\n";
    close(server_fd_);
    server_fd_ = -1;
    return false;
  }

  if (listen(server_fd_, 10) < 0) {
    std::cerr << "[Dashboard] Listen failed: " << strerror(errno) << "\n";
    close(server_fd_);
    server_fd_ = -1;
    return false;
  }

  running_.store(true);
  server_thread_ = std::thread(&DashboardServer::serverLoop, this);

  std::cout << "[Dashboard] Server started at http://localhost:" << port_
            << "\n";
  return true;
}

void DashboardServer::stop() {
  running_.store(false);
  if (server_fd_ >= 0) {
    shutdown(server_fd_, SHUT_RDWR);
    close(server_fd_);
    server_fd_ = -1;
  }
  if (server_thread_.joinable()) {
    server_thread_.join();
  }
}

void DashboardServer::serverLoop() {
  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  setsockopt(server_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  while (running_.load()) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd =
        accept(server_fd_, (struct sockaddr *)&client_addr, &client_len);

    if (client_fd < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        continue;
      if (running_.load())
        continue;
      break;
    }

    handleClient(client_fd);
  }
}

// ============================================================================
// SHA-1 for WebSocket handshake (RFC 6455)
// ============================================================================
static void sha1(const uint8_t *data, size_t len, uint8_t hash[20]) {
  uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476,
           h4 = 0xC3D2E1F0;

  // Pre-processing
  size_t new_len = len + 1;
  while (new_len % 64 != 56)
    new_len++;
  std::vector<uint8_t> msg(new_len + 8, 0);
  std::memcpy(msg.data(), data, len);
  msg[len] = 0x80;
  uint64_t bit_len = len * 8;
  for (int i = 0; i < 8; i++)
    msg[new_len + i] = (bit_len >> (56 - i * 8)) & 0xFF;

  auto leftRotate = [](uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
  };

  for (size_t offset = 0; offset < msg.size(); offset += 64) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
      w[i] = (msg[offset + i * 4] << 24) | (msg[offset + i * 4 + 1] << 16) |
             (msg[offset + i * 4 + 2] << 8) | msg[offset + i * 4 + 3];
    for (int i = 16; i < 80; i++)
      w[i] = leftRotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
    for (int i = 0; i < 80; i++) {
      uint32_t f, k;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 0x5A827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }
      uint32_t temp = leftRotate(a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = leftRotate(b, 30);
      b = a;
      a = temp;
    }
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
  }

  for (int i = 0; i < 4; i++) {
    hash[i] = (h0 >> (24 - i * 8)) & 0xFF;
    hash[4 + i] = (h1 >> (24 - i * 8)) & 0xFF;
    hash[8 + i] = (h2 >> (24 - i * 8)) & 0xFF;
    hash[12 + i] = (h3 >> (24 - i * 8)) & 0xFF;
    hash[16 + i] = (h4 >> (24 - i * 8)) & 0xFF;
  }
}

static std::string base64Encode(const uint8_t *data, size_t len) {
  static const char table[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string result;
  result.reserve(((len + 2) / 3) * 4);
  for (size_t i = 0; i < len; i += 3) {
    uint32_t n = (static_cast<uint32_t>(data[i]) << 16);
    if (i + 1 < len)
      n |= (static_cast<uint32_t>(data[i + 1]) << 8);
    if (i + 2 < len)
      n |= static_cast<uint32_t>(data[i + 2]);
    result += table[(n >> 18) & 63];
    result += table[(n >> 12) & 63];
    result += (i + 1 < len) ? table[(n >> 6) & 63] : '=';
    result += (i + 2 < len) ? table[n & 63] : '=';
  }
  return result;
}

// ============================================================================
// WebSocket frame encoding
// ============================================================================
static std::vector<uint8_t> wsFrame(const std::string &payload) {
  std::vector<uint8_t> frame;
  frame.push_back(0x81); // FIN + text opcode
  size_t len = payload.size();
  if (len <= 125) {
    frame.push_back(static_cast<uint8_t>(len));
  } else if (len <= 65535) {
    frame.push_back(126);
    frame.push_back((len >> 8) & 0xFF);
    frame.push_back(len & 0xFF);
  } else {
    frame.push_back(127);
    for (int i = 7; i >= 0; i--)
      frame.push_back((len >> (i * 8)) & 0xFF);
  }
  frame.insert(frame.end(), payload.begin(), payload.end());
  return frame;
}

// ============================================================================
// Client handling with WebSocket upgrade support
// ============================================================================
void DashboardServer::handleClient(int client_fd) {
  char buffer[4096];
  ssize_t bytes = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
  if (bytes <= 0) {
    close(client_fd);
    return;
  }
  buffer[bytes] = '\0';

  std::string request(buffer);
  std::string method, path;
  std::istringstream iss(request);
  iss >> method >> path;

  if (method != "GET") {
    sendResponse(client_fd, 405, "text/plain", "Method Not Allowed");
    close(client_fd);
    return;
  }

  // Check for WebSocket upgrade
  if (request.find("Upgrade: websocket") != std::string::npos ||
      request.find("Upgrade: Websocket") != std::string::npos) {
    // Extract Sec-WebSocket-Key
    std::string ws_key;
    auto key_pos = request.find("Sec-WebSocket-Key: ");
    if (key_pos != std::string::npos) {
      auto key_start = key_pos + 19;
      auto key_end = request.find("\r\n", key_start);
      ws_key = request.substr(key_start, key_end - key_start);
    }

    if (ws_key.empty()) {
      sendResponse(client_fd, 400, "text/plain", "Bad Request");
      close(client_fd);
      return;
    }

    // Compute accept key (RFC 6455)
    std::string magic = ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t sha_hash[20];
    sha1(reinterpret_cast<const uint8_t *>(magic.c_str()), magic.size(),
         sha_hash);
    std::string accept_key = base64Encode(sha_hash, 20);

    // Send upgrade response
    std::ostringstream resp;
    resp << "HTTP/1.1 101 Switching Protocols\r\n";
    resp << "Upgrade: websocket\r\n";
    resp << "Connection: Upgrade\r\n";
    resp << "Sec-WebSocket-Accept: " << accept_key << "\r\n";
    resp << "\r\n";
    std::string resp_str = resp.str();
    send(client_fd, resp_str.c_str(), resp_str.size(), 0);

    // WebSocket loop — push stats every second
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000; // 100ms timeout for recv
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (running_.load()) {
      // Send stats
      std::string json = "{}";
      if (stats_provider_)
        json = stats_provider_();
      auto frame = wsFrame(json);
      ssize_t sent = send(client_fd, frame.data(), frame.size(), MSG_NOSIGNAL);
      if (sent <= 0)
        break;

      // Wait ~1 second, checking for close frames / pings
      for (int i = 0; i < 10 && running_.load(); i++) {
        char ws_buf[256];
        ssize_t ws_bytes = recv(client_fd, ws_buf, sizeof(ws_buf), 0);
        if (ws_bytes > 0) {
          uint8_t opcode = ws_buf[0] & 0x0F;
          if (opcode == 0x08)
            goto ws_done;       // Close frame
          if (opcode == 0x09) { // Ping → Pong
            ws_buf[0] = (ws_buf[0] & 0xF0) | 0x0A;
            send(client_fd, ws_buf, ws_bytes, 0);
          }
        }
      }
    }
  ws_done:
    close(client_fd);
    return;
  }

  // Regular HTTP
  if (path == "/" || path == "/index.html") {
    sendResponse(client_fd, 200, "text/html", getDashboardHTML());
  } else if (path == "/api/stats") {
    std::string json = "{}";
    if (stats_provider_)
      json = stats_provider_();
    sendResponse(client_fd, 200, "application/json", json);
  } else {
    sendResponse(client_fd, 404, "text/plain", "Not Found");
  }
  close(client_fd);
}

void DashboardServer::sendResponse(int client_fd, int status_code,
                                   const std::string &content_type,
                                   const std::string &body) {
  std::ostringstream response;
  response << "HTTP/1.1 " << status_code << " " << getStatusText(status_code)
           << "\r\n";
  response << "Content-Type: " << content_type << "; charset=utf-8\r\n";
  response << "Content-Length: " << body.size() << "\r\n";
  response << "Access-Control-Allow-Origin: *\r\n";
  response << "Connection: close\r\n";
  response << "\r\n";
  response << body;

  std::string resp_str = response.str();
  send(client_fd, resp_str.c_str(), resp_str.size(), 0);
}

std::string DashboardServer::getStatusText(int status_code) {
  switch (status_code) {
  case 200:
    return "OK";
  case 400:
    return "Bad Request";
  case 404:
    return "Not Found";
  case 405:
    return "Method Not Allowed";
  default:
    return "Unknown";
  }
}

// ============================================================================
// Enhanced Dashboard HTML with WebSocket, GeoIP Map, IDS Alerts, JA3 Panel
// ============================================================================
std::string DashboardServer::getDashboardHTML() {
  return R"HTML(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetSpectre — Deep Packet Inspection Dashboard</title>
    <meta name="description" content="Real-time Deep Packet Inspection with IDS, JA3 Fingerprinting & GeoIP">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap');

        :root {
            --bg-primary: #05070e;
            --bg-secondary: #0c1120;
            --bg-card: rgba(12, 17, 32, 0.85);
            --bg-card-hover: rgba(20, 28, 50, 0.9);
            --border: rgba(99, 102, 241, 0.15);
            --border-hover: rgba(99, 102, 241, 0.4);
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --text-muted: #475569;
            --accent: #6366f1;
            --accent2: #06b6d4;
            --green: #10b981;
            --red: #f43f5e;
            --amber: #f59e0b;
            --violet: #8b5cf6;
            --pink: #ec4899;
            --glow: rgba(99, 102, 241, 0.15);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', system-ui, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
        }

        body::before {
            content: '';
            position: fixed;
            inset: 0;
            background:
                radial-gradient(ellipse 80% 50% at 20% 20%, rgba(99,102,241,0.07) 0%, transparent 70%),
                radial-gradient(ellipse 60% 40% at 80% 80%, rgba(6,182,212,0.05) 0%, transparent 70%),
                radial-gradient(ellipse 50% 50% at 50% 50%, rgba(139,92,246,0.03) 0%, transparent 70%);
            animation: bgPulse 25s ease-in-out infinite alternate;
            z-index: 0;
            pointer-events: none;
        }

        @keyframes bgPulse {
            0% { opacity: 1; }
            100% { opacity: 0.6; transform: scale(1.05); }
        }

        .dash { max-width: 1500px; margin: 0 auto; padding: 20px; position: relative; z-index: 1; }

        /* Header */
        .header {
            display: flex; align-items: center; justify-content: space-between;
            padding: 16px 24px; margin-bottom: 20px;
            background: var(--bg-card); backdrop-filter: blur(24px);
            border: 1px solid var(--border); border-radius: 14px;
            box-shadow: 0 0 40px var(--glow);
        }
        .header h1 {
            font-size: 22px; font-weight: 800;
            background: linear-gradient(135deg, var(--accent), var(--accent2));
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .header .sub { color: var(--text-muted); font-size: 12px; margin-top: 2px; }
        .ws-badge {
            display: flex; align-items: center; gap: 8px;
            padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: 600;
        }
        .ws-badge.connected { background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.3); color: var(--green); }
        .ws-badge.disconnected { background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.3); color: var(--red); }
        .ws-dot { width: 8px; height: 8px; border-radius: 50%; animation: dot 2s ease infinite; }
        .ws-badge.connected .ws-dot { background: var(--green); }
        .ws-badge.disconnected .ws-dot { background: var(--red); animation: none; }
        @keyframes dot { 0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(16,185,129,0.4)} 50%{opacity:.6;box-shadow:0 0 0 6px rgba(16,185,129,0)} }

        /* Stats Row */
        .stats { display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; margin-bottom: 20px; }
        @media(max-width:1200px) { .stats { grid-template-columns: repeat(3, 1fr); } }
        @media(max-width:600px) { .stats { grid-template-columns: repeat(2, 1fr); } }
        .sc {
            padding: 16px 18px; background: var(--bg-card); backdrop-filter: blur(20px);
            border: 1px solid var(--border); border-radius: 12px;
            transition: all .3s; position: relative; overflow: hidden;
        }
        .sc::before { content:''; position:absolute; top:0; left:0; width:100%; height:2px; background: linear-gradient(90deg, var(--ca, var(--accent)), transparent); }
        .sc:hover { transform: translateY(-2px); border-color: var(--ca, var(--accent)); box-shadow: 0 8px 24px rgba(0,0,0,.3); }
        .sc .lb { font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: .08em; color: var(--text-muted); margin-bottom: 6px; }
        .sc .vl { font-size: 24px; font-weight: 700; font-variant-numeric: tabular-nums; }
        .sc .ch { font-size: 11px; color: var(--text-secondary); margin-top: 3px; }
        .sc:nth-child(1){--ca:var(--accent)} .sc:nth-child(2){--ca:var(--green)} .sc:nth-child(3){--ca:var(--red)}
        .sc:nth-child(4){--ca:var(--accent2)} .sc:nth-child(5){--ca:var(--amber)} .sc:nth-child(6){--ca:var(--violet)}

        /* Grid layouts */
        .g2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
        .g3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin-bottom: 16px; }
        .g1 { display: grid; grid-template-columns: 1fr; gap: 16px; margin-bottom: 16px; }
        @media(max-width:1000px) { .g2,.g3 { grid-template-columns: 1fr; } }

        /* Panel */
        .pn {
            background: var(--bg-card); backdrop-filter: blur(20px);
            border: 1px solid var(--border); border-radius: 12px;
            padding: 20px; transition: border-color .3s;
        }
        .pn:hover { border-color: var(--border-hover); }
        .pn-title {
            font-size: 13px; font-weight: 600; margin-bottom: 16px;
            display: flex; align-items: center; gap: 8px;
        }
        .pn-title .ic { font-size: 16px; }

        /* World Map (SVG viewBox) */
        .map-container { position: relative; width: 100%; aspect-ratio: 2/1; overflow: hidden; border-radius: 8px; background: rgba(5,7,14,0.6); }
        .map-container svg { width: 100%; height: 100%; }
        .map-dot {
            fill: var(--accent2); opacity: 0.8;
            filter: drop-shadow(0 0 6px rgba(6,182,212,0.6));
            animation: mapPulse 2s ease-in-out infinite;
        }
        @keyframes mapPulse { 0%,100%{r:3;opacity:.8} 50%{r:5;opacity:1} }
        .map-ring {
            fill: none; stroke: var(--accent2); stroke-width: 0.5; opacity: 0;
            animation: ringPulse 2s ease-out infinite;
        }
        @keyframes ringPulse { 0%{r:3;opacity:.6} 100%{r:15;opacity:0} }
        .map-label { font-family: 'Inter'; font-size: 3px; fill: var(--text-secondary); text-anchor: middle; }
        .map-grid { stroke: rgba(99,102,241,0.06); stroke-width: 0.2; fill: none; }
        .map-outline { fill: rgba(99,102,241,0.04); stroke: rgba(99,102,241,0.12); stroke-width: 0.2; }

        /* Country list */
        .geo-list { list-style: none; max-height: 260px; overflow-y: auto; }
        .geo-item { display: flex; align-items: center; gap: 10px; padding: 7px 0; border-bottom: 1px solid rgba(255,255,255,.03); font-size: 13px; }
        .geo-item:last-child { border-bottom: none; }
        .geo-flag { font-size: 16px; }
        .geo-name { flex: 1; font-weight: 500; }
        .geo-count { font-size: 12px; color: var(--text-secondary); font-variant-numeric: tabular-nums; }

        /* App bars */
        .app-list { list-style: none; }
        .app-item { display: flex; align-items: center; gap: 10px; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,.04); }
        .app-item:last-child { border-bottom: none; }
        .app-name { font-size: 12px; font-weight: 500; width: 100px; flex-shrink: 0; }
        .app-bar-track { flex: 1; height: 6px; background: rgba(255,255,255,.04); border-radius: 3px; overflow: hidden; }
        .app-bar-fill { height: 100%; border-radius: 3px; transition: width .8s ease; min-width: 2px; }
        .app-count { font-size: 11px; font-weight: 600; color: var(--text-secondary); width: 50px; text-align: right; font-variant-numeric: tabular-nums; }
        .app-pct { font-size: 10px; color: var(--text-muted); width: 40px; text-align: right; }

        /* SNI list */
        .sni-list { list-style: none; max-height: 260px; overflow-y: auto; }
        .sni-item { padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,.03); display: flex; justify-content: space-between; align-items: center; }
        .sni-item:last-child { border-bottom: none; }
        .sni-domain { font-size: 12px; font-weight: 500; color: var(--accent2); word-break: break-all; }

        /* Alert panel */
        .alert-list { list-style: none; max-height: 200px; overflow-y: auto; }
        .alert-item { padding: 8px 10px; margin-bottom: 6px; border-radius: 8px; font-size: 12px; display: flex; align-items: flex-start; gap: 8px; }
        .alert-item.critical { background: rgba(244,63,94,0.08); border-left: 3px solid var(--red); }
        .alert-item.high { background: rgba(245,158,11,0.08); border-left: 3px solid var(--amber); }
        .alert-item.medium { background: rgba(99,102,241,0.08); border-left: 3px solid var(--accent); }
        .alert-item.low { background: rgba(16,185,129,0.08); border-left: 3px solid var(--green); }
        .alert-sev { font-weight: 700; font-size: 10px; text-transform: uppercase; letter-spacing: .05em; min-width: 60px; }
        .alert-desc { color: var(--text-secondary); line-height: 1.4; }

        /* JA3 panel */
        .ja3-list { list-style: none; max-height: 200px; overflow-y: auto; }
        .ja3-item { padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,.03); display: flex; justify-content: space-between; align-items: center; gap: 8px; }
        .ja3-item:last-child { border-bottom: none; }
        .ja3-hash { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text-muted); }
        .ja3-app { font-size: 12px; font-weight: 500; color: var(--violet); }

        /* Flow table */
        .flow-wrap { overflow-x: auto; }
        .ft { width: 100%; border-collapse: collapse; font-size: 12px; }
        .ft th { padding: 8px 10px; text-align: left; font-weight: 600; font-size: 10px; text-transform: uppercase; letter-spacing: .05em; color: var(--text-muted); border-bottom: 1px solid var(--border); }
        .ft td { padding: 8px 10px; border-bottom: 1px solid rgba(255,255,255,.03); color: var(--text-secondary); font-variant-numeric: tabular-nums; }
        .ft tr:hover td { background: rgba(99,102,241,0.04); color: var(--text-primary); }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 600; }
        .badge-fwd { background: rgba(16,185,129,0.12); color: var(--green); }
        .badge-blk { background: rgba(244,63,94,0.12); color: var(--red); }
        .badge-app { background: rgba(99,102,241,0.12); color: var(--accent); }
        .badge-geo { background: rgba(6,182,212,0.1); color: var(--accent2); font-size: 10px; padding: 1px 6px; }

        .no-data { color: var(--text-muted); font-size: 12px; font-style: italic; }
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(99,102,241,0.2); border-radius: 3px; }
    </style>
</head>
<body>
    <div class="dash">
        <header class="header">
            <div>
                <h1>🛡️ NetSpectre — DPI</h1>
                <p class="sub">Deep Packet Inspection • IDS • JA3 Fingerprinting • GeoIP</p>
            </div>
            <div class="ws-badge disconnected" id="wsBadge">
                <span class="ws-dot"></span>
                <span id="wsStatus">Connecting...</span>
            </div>
        </header>

        <div class="stats">
            <div class="sc"><div class="lb">Total Packets</div><div class="vl" id="sPkts">—</div><div class="ch" id="sPps">waiting...</div></div>
            <div class="sc"><div class="lb">Forwarded</div><div class="vl" id="sFwd">—</div><div class="ch" id="sFwdP"></div></div>
            <div class="sc"><div class="lb">Dropped</div><div class="vl" id="sDrp">—</div><div class="ch" id="sDrpP"></div></div>
            <div class="sc"><div class="lb">Active Flows</div><div class="vl" id="sFlw">—</div></div>
            <div class="sc"><div class="lb">Total Bytes</div><div class="vl" id="sByt">—</div></div>
            <div class="sc"><div class="lb">IDS Alerts</div><div class="vl" id="sAlt">0</div><div class="ch" id="sAltS">no anomalies</div></div>
        </div>

        <div class="g2">
            <div class="pn">
                <div class="pn-title"><span class="ic">🌍</span> GeoIP — Traffic Origins</div>
                <div class="map-container" id="mapContainer">
                    <svg viewBox="-180 -90 360 180" id="worldMap" preserveAspectRatio="xMidYMid meet">
                        <!-- Grid lines -->
                        <line x1="-180" y1="0" x2="180" y2="0" class="map-grid"/>
                        <line x1="0" y1="-90" x2="0" y2="90" class="map-grid"/>
                        <line x1="-180" y1="-45" x2="180" y2="-45" class="map-grid" stroke-dasharray="2,4"/>
                        <line x1="-180" y1="45" x2="180" y2="45" class="map-grid" stroke-dasharray="2,4"/>
                        <line x1="-90" y1="-90" x2="-90" y2="90" class="map-grid" stroke-dasharray="2,4"/>
                        <line x1="90" y1="-90" x2="90" y2="90" class="map-grid" stroke-dasharray="2,4"/>
                        <!-- Simplified continent outlines -->
                        <ellipse cx="-100" cy="-35" rx="25" ry="30" class="map-outline"/>
                        <ellipse cx="-75" cy="15" rx="15" ry="25" class="map-outline"/>
                        <ellipse cx="10" cy="-40" rx="20" ry="20" class="map-outline"/>
                        <ellipse cx="15" cy="10" rx="18" ry="28" class="map-outline"/>
                        <ellipse cx="80" cy="-30" rx="40" ry="25" class="map-outline"/>
                        <ellipse cx="130" cy="30" rx="20" ry="15" class="map-outline"/>
                        <g id="mapDots"></g>
                    </svg>
                </div>
            </div>
            <div class="pn">
                <div class="pn-title"><span class="ic">📍</span> Countries</div>
                <ul class="geo-list" id="geoList"><li class="no-data">Waiting for data...</li></ul>
            </div>
        </div>

        <div class="g3">
            <div class="pn">
                <div class="pn-title"><span class="ic">📊</span> Application Breakdown</div>
                <ul class="app-list" id="appList"><li class="no-data">Waiting for data...</li></ul>
            </div>
            <div class="pn">
                <div class="pn-title"><span class="ic">🌐</span> Detected Domains (SNI)</div>
                <ul class="sni-list" id="sniList"><li class="no-data">Waiting for data...</li></ul>
            </div>
            <div class="pn">
                <div class="pn-title"><span class="ic">🔐</span> JA3 TLS Fingerprints</div>
                <ul class="ja3-list" id="ja3List"><li class="no-data">Waiting for data...</li></ul>
            </div>
        </div>

        <div class="g2">
            <div class="pn">
                <div class="pn-title"><span class="ic">🚨</span> IDS Alerts</div>
                <ul class="alert-list" id="alertList"><li class="no-data">No anomalies detected</li></ul>
            </div>
            <div class="pn flow-wrap">
                <div class="pn-title"><span class="ic">🔄</span> Top Flows</div>
                <div style="overflow-x:auto">
                    <table class="ft">
                        <thead><tr><th>Source</th><th>Destination</th><th>Proto</th><th>App</th><th>SNI</th><th>Pkts</th><th>Geo</th><th>Status</th></tr></thead>
                        <tbody id="flowBody"><tr><td colspan="8" class="no-data" style="text-align:center">Waiting...</td></tr></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script>
    const COLORS = ['#6366f1','#06b6d4','#10b981','#f59e0b','#f43f5e','#8b5cf6','#ec4899','#14b8a6','#f97316','#84cc16','#0ea5e9','#d946ef'];
    const FLAGS = {US:'🇺🇸',GB:'🇬🇧',DE:'🇩🇪',FR:'🇫🇷',NL:'🇳🇱',SE:'🇸🇪',RU:'🇷🇺',IT:'🇮🇹',ES:'🇪🇸',PL:'🇵🇱',CN:'🇨🇳',JP:'🇯🇵',KR:'🇰🇷',IN:'🇮🇳',SG:'🇸🇬',AU:'🇦🇺',BR:'🇧🇷',ZA:'🇿🇦',CA:'🇨🇦','--':'🌐',XX:'🏠'};
    let prevPkts = 0, prevTime = Date.now();

    function fmt(n) { if(n==null) return '—'; if(n>=1e9) return (n/1e9).toFixed(1)+'B'; if(n>=1e6) return (n/1e6).toFixed(1)+'M'; if(n>=1e3) return (n/1e3).toFixed(1)+'K'; return n.toLocaleString(); }
    function fmtB(b) { if(b==null) return '—'; if(b>=1e9) return (b/1e9).toFixed(2)+' GB'; if(b>=1e6) return (b/1e6).toFixed(2)+' MB'; if(b>=1e3) return (b/1e3).toFixed(1)+' KB'; return b+' B'; }

    // WebSocket connection
    let ws = null;
    function connectWS() {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(proto + '//' + location.host + '/ws');
        const badge = document.getElementById('wsBadge');
        const status = document.getElementById('wsStatus');

        ws.onopen = () => { badge.className = 'ws-badge connected'; status.textContent = 'WebSocket Live'; };
        ws.onclose = () => { badge.className = 'ws-badge disconnected'; status.textContent = 'Reconnecting...'; setTimeout(connectWS, 2000); };
        ws.onerror = () => ws.close();
        ws.onmessage = (e) => {
            try { updateDashboard(JSON.parse(e.data)); } catch(err) {}
        };
    }

    // Fallback to polling if WS fails
    let pollFallback = null;
    function startPolling() {
        if (pollFallback) return;
        pollFallback = setInterval(async () => {
            try {
                const r = await fetch('/api/stats');
                const d = await r.json();
                updateDashboard(d);
                document.getElementById('wsStatus').textContent = 'Polling';
            } catch(e) {}
        }, 2000);
    }

    function updateDashboard(d) {
        const total = d.total_packets||0, fwd = d.forwarded||0, drp = d.dropped||0;
        const now = Date.now(), elapsed = (now-prevTime)/1000;
        const pps = elapsed > 0 ? ((total-prevPkts)/elapsed) : 0;
        prevPkts = total; prevTime = now;

        document.getElementById('sPkts').textContent = fmt(total);
        document.getElementById('sFwd').textContent = fmt(fwd);
        document.getElementById('sDrp').textContent = fmt(drp);
        document.getElementById('sFlw').textContent = fmt(d.active_flows||0);
        document.getElementById('sByt').textContent = fmtB(d.total_bytes||0);
        document.getElementById('sPps').textContent = pps > 0 ? pps.toFixed(0)+' pps' : '0 pps';
        document.getElementById('sFwdP').textContent = total > 0 ? (fwd/total*100).toFixed(1)+'%' : '';
        document.getElementById('sDrpP').textContent = total > 0 ? (drp/total*100).toFixed(1)+'%' : '';

        // Alerts count
        const alerts = d.alerts || [];
        document.getElementById('sAlt').textContent = alerts.length;
        document.getElementById('sAltS').textContent = alerts.length > 0 ?
            alerts.filter(a=>a.severity==='CRITICAL'||a.severity==='HIGH').length + ' critical/high' : 'no anomalies';

        // App breakdown
        const apps = d.app_breakdown || {};
        const al = document.getElementById('appList');
        const ae = Object.entries(apps).sort((a,b) => b[1]-a[1]);
        if (!ae.length) { al.innerHTML = '<li class="no-data">No traffic yet</li>'; }
        else {
            const mx = ae[0][1];
            al.innerHTML = ae.map(([n,c],i) => {
                const p = total > 0 ? (c/total*100) : 0, cl = COLORS[i%COLORS.length], w = mx>0?(c/mx*100):0;
                return `<li class="app-item"><span class="app-name" style="color:${cl}">${n}</span><div class="app-bar-track"><div class="app-bar-fill" style="width:${w}%;background:${cl}"></div></div><span class="app-count">${fmt(c)}</span><span class="app-pct">${p.toFixed(1)}%</span></li>`;
            }).join('');
        }

        // SNI list
        const snis = d.detected_snis || {};
        const sl = document.getElementById('sniList');
        const se = Object.entries(snis).slice(0,15);
        if (!se.length) { sl.innerHTML = '<li class="no-data">No domains yet</li>'; }
        else { sl.innerHTML = se.map(([dom,app]) => `<li class="sni-item"><span class="sni-domain">${dom}</span><span class="badge badge-app">${app}</span></li>`).join(''); }

        // JA3 fingerprints
        const ja3 = d.ja3_fingerprints || {};
        const jl = document.getElementById('ja3List');
        const je = Object.entries(ja3).slice(0,10);
        if (!je.length) { jl.innerHTML = '<li class="no-data">No TLS fingerprints yet</li>'; }
        else { jl.innerHTML = je.map(([h,a]) => `<li class="ja3-item"><span class="ja3-hash">${h.substring(0,16)}...</span><span class="ja3-app">${a}</span></li>`).join(''); }

        // IDS Alerts
        const alertEl = document.getElementById('alertList');
        if (!alerts.length) { alertEl.innerHTML = '<li class="no-data">No anomalies detected — traffic appears normal</li>'; }
        else {
            alertEl.innerHTML = alerts.slice(0,10).map(a => {
                const cls = (a.severity||'').toLowerCase();
                return `<li class="alert-item ${cls}"><span class="alert-sev" style="color:${cls==='critical'?'var(--red)':cls==='high'?'var(--amber)':'var(--accent)'}">${a.severity}</span><span class="alert-desc"><strong>${a.type}</strong>: ${a.description}</span></li>`;
            }).join('');
        }

        // GeoIP map + country list
        const geos = d.geo_locations || [];
        const mapDots = document.getElementById('mapDots');
        const geoList = document.getElementById('geoList');

        if (geos.length > 0) {
            // Group by country
            const byCountry = {};
            geos.forEach(g => {
                if (!byCountry[g.cc]) byCountry[g.cc] = { name: g.country, lat: g.lat, lng: g.lng, packets: 0, count: 0 };
                byCountry[g.cc].packets += g.packets;
                byCountry[g.cc].count++;
            });

            // Map dots
            let dotsHTML = '';
            geos.forEach((g, i) => {
                const x = g.lng, y = -g.lat; // SVG y is inverted
                const delay = (i * 0.3) % 2;
                dotsHTML += `<circle cx="${x}" cy="${y}" r="3" class="map-dot" style="animation-delay:${delay}s"/>`;
                dotsHTML += `<circle cx="${x}" cy="${y}" r="3" class="map-ring" style="animation-delay:${delay}s"/>`;
                dotsHTML += `<text x="${x}" y="${y-6}" class="map-label">${g.cc}</text>`;
            });
            mapDots.innerHTML = dotsHTML;

            // Country list
            const sorted = Object.entries(byCountry).sort((a,b) => b[1].packets - a[1].packets);
            geoList.innerHTML = sorted.map(([cc, info]) =>
                `<li class="geo-item"><span class="geo-flag">${FLAGS[cc]||'🌐'}</span><span class="geo-name">${info.name}</span><span class="geo-count">${fmt(info.packets)} pkts · ${info.count} IPs</span></li>`
            ).join('');
        }

        // Flow table
        const flows = d.top_flows || [];
        const fb = document.getElementById('flowBody');
        if (!flows.length) { fb.innerHTML = '<tr><td colspan="8" class="no-data" style="text-align:center">No flows yet</td></tr>'; }
        else {
            fb.innerHTML = flows.slice(0,15).map(f => {
                const proto = f.protocol===6?'TCP':f.protocol===17?'UDP':f.protocol;
                const geo = f.dst_ip ? '' : '';
                return `<tr>
                    <td>${f.src_ip||'—'}:${f.src_port||''}</td>
                    <td>${f.dst_ip||'—'}:${f.dst_port||''}</td>
                    <td>${proto}</td>
                    <td><span class="badge badge-app">${f.app||'Unknown'}</span></td>
                    <td style="color:var(--accent2);font-size:11px;max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${f.sni||'—'}</td>
                    <td>${fmt(f.packets)}</td>
                    <td>${f.ja3_app ? '<span class="badge badge-geo">'+f.ja3_app.substring(0,12)+'</span>' : '—'}</td>
                    <td>${f.blocked?'<span class="badge badge-blk">Blocked</span>':'<span class="badge badge-fwd">Forward</span>'}</td>
                </tr>`;
            }).join('');
        }
    }

    // Start WebSocket, with polling fallback
    try { connectWS(); } catch(e) { startPolling(); }
    setTimeout(() => { if (!ws || ws.readyState !== 1) startPolling(); }, 5000);
    </script>
</body>
</html>
)HTML";
}

} // namespace DPI
