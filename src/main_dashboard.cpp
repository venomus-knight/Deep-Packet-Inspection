// DPI Engine - Dashboard Mode
// Processes PCAP files or live capture and serves a real-time web dashboard
//
// Usage: ./dpi_dashboard --pcap input.pcap [--port 8080]
//    or: sudo ./dpi_dashboard --interface en0 [--port 8080]

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "anomaly_detector.h"
#include "dashboard_server.h"
#include "geoip.h"
#include "ja3_fingerprint.h"
#include "live_capture.h"
#include "packet_parser.h"
#include "pcap_reader.h"
#include "sni_extractor.h"
#include "types.h"

using namespace PacketAnalyzer;
using namespace DPI;

// ============================================================================
// Global state
// ============================================================================
static std::atomic<bool> g_running{true};
static LiveCapture *g_live_capture = nullptr;

void signalHandler(int signum) {
  (void)signum;
  g_running.store(false);
  if (g_live_capture)
    g_live_capture->stop();
}

// ============================================================================
// Shared statistics for the dashboard
// ============================================================================
struct DashboardFlow {
  FiveTuple tuple;
  AppType app_type = AppType::UNKNOWN;
  std::string sni;
  std::string ja3_hash;
  std::string ja3_app;
  uint64_t packets = 0;
  uint64_t bytes = 0;
  bool blocked = false;
};

struct DashboardStats {
  std::mutex mutex;
  uint64_t total_packets = 0;
  uint64_t total_bytes = 0;
  uint64_t forwarded = 0;
  uint64_t dropped = 0;
  std::unordered_map<AppType, uint64_t> app_counts;
  std::unordered_map<std::string, AppType> detected_snis;
  std::unordered_map<std::string, std::string> detected_ja3; // hash -> app
  AnomalyDetector ids;
  std::unordered_map<FiveTuple, DashboardFlow, FiveTupleHash> flows;
  std::unordered_map<std::string, std::string> dns_ip_to_domain;
  bool processing_complete = false;
};

// ============================================================================
// Blocking Rules
// ============================================================================
class DashboardBlockingRules {
public:
  std::unordered_set<uint32_t> blocked_ips;
  std::unordered_set<AppType> blocked_apps;
  std::vector<std::string> blocked_domains;

  void blockIP(const std::string &ip) {
    blocked_ips.insert(parseIP(ip));
    std::cout << "[Rules] Blocked IP: " << ip << "\n";
  }
  void blockApp(const std::string &app) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
      if (appTypeToString(static_cast<AppType>(i)) == app) {
        blocked_apps.insert(static_cast<AppType>(i));
        std::cout << "[Rules] Blocked app: " << app << "\n";
        return;
      }
    }
  }
  void blockDomain(const std::string &domain) {
    blocked_domains.push_back(domain);
    std::cout << "[Rules] Blocked domain: " << domain << "\n";
  }
  bool isBlocked(uint32_t src_ip, AppType app, const std::string &sni) const {
    if (blocked_ips.count(src_ip))
      return true;
    if (blocked_apps.count(app))
      return true;
    for (const auto &dom : blocked_domains) {
      if (sni.find(dom) != std::string::npos)
        return true;
    }
    return false;
  }
  static uint32_t parseIP(const std::string &ip) {
    uint32_t result = 0;
    int octet = 0, shift = 0;
    for (char c : ip) {
      if (c == '.') {
        result |= (octet << shift);
        shift += 8;
        octet = 0;
      } else if (c >= '0' && c <= '9')
        octet = octet * 10 + (c - '0');
    }
    return result | (octet << shift);
  }
};

// ============================================================================
// JSON serialization for stats
// ============================================================================
std::string formatIP(uint32_t ip) {
  std::ostringstream ss;
  ss << (ip & 0xFF) << "." << ((ip >> 8) & 0xFF) << "." << ((ip >> 16) & 0xFF)
     << "." << ((ip >> 24) & 0xFF);
  return ss.str();
}

std::string escapeJSON(const std::string &s) {
  std::string result;
  for (char c : s) {
    if (c == '"')
      result += "\\\"";
    else if (c == '\\')
      result += "\\\\";
    else if (c == '\n')
      result += "\\n";
    else
      result += c;
  }
  return result;
}

std::string statsToJSON(DashboardStats &stats) {
  std::lock_guard<std::mutex> lock(stats.mutex);
  std::ostringstream json;

  json << "{";
  json << "\"total_packets\":" << stats.total_packets << ",";
  json << "\"total_bytes\":" << stats.total_bytes << ",";
  json << "\"forwarded\":" << stats.forwarded << ",";
  json << "\"dropped\":" << stats.dropped << ",";
  json << "\"active_flows\":" << stats.flows.size() << ",";
  json << "\"processing_complete\":"
       << (stats.processing_complete ? "true" : "false") << ",";

  // App breakdown
  json << "\"app_breakdown\":{";
  bool first = true;
  std::vector<std::pair<AppType, uint64_t>> sorted_apps(
      stats.app_counts.begin(), stats.app_counts.end());
  std::sort(sorted_apps.begin(), sorted_apps.end(),
            [](const auto &a, const auto &b) { return a.second > b.second; });
  for (const auto &[app, count] : sorted_apps) {
    if (!first)
      json << ",";
    json << "\"" << escapeJSON(appTypeToString(app)) << "\":" << count;
    first = false;
  }
  json << "},";

  // Detected SNIs
  json << "\"detected_snis\":{";
  first = true;
  int sni_count = 0;
  for (const auto &[sni, app] : stats.detected_snis) {
    if (sni_count >= 20)
      break;
    if (!first)
      json << ",";
    json << "\"" << escapeJSON(sni) << "\":\""
         << escapeJSON(appTypeToString(app)) << "\"";
    first = false;
    sni_count++;
  }
  json << "},";

  // Alerts from IDS
  json << "\"alerts\":[";
  first = true;
  auto alerts = stats.ids.peekAlerts();
  for (const auto &alert : alerts) {
    if (!first)
      json << ",";
    json << "{\"type\":\""
         << escapeJSON(AnomalyDetector::alertTypeToString(alert.type))
         << "\",\"severity\":\""
         << escapeJSON(AnomalyDetector::severityToString(alert.severity))
         << "\",\"description\":\"" << escapeJSON(alert.description) << "\"}";
    first = false;
  }
  json << "],";

  // Top flows (by packet count)
  json << "\"top_flows\":[";
  std::vector<const DashboardFlow *> sorted_flows;
  for (const auto &[tuple, flow] : stats.flows) {
    sorted_flows.push_back(&flow);
  }
  std::sort(
      sorted_flows.begin(), sorted_flows.end(),
      [](const auto *a, const auto *b) { return a->packets > b->packets; });

  first = true;
  int flow_count = 0;
  for (const auto *flow : sorted_flows) {
    if (flow_count >= 20)
      break;
    if (!first)
      json << ",";
    json << "{";
    json << "\"src_ip\":\"" << formatIP(flow->tuple.src_ip) << "\",";
    json << "\"dst_ip\":\"" << formatIP(flow->tuple.dst_ip) << "\",";
    json << "\"src_port\":" << flow->tuple.src_port << ",";
    json << "\"dst_port\":" << flow->tuple.dst_port << ",";
    json << "\"protocol\":" << static_cast<int>(flow->tuple.protocol) << ",";
    json << "\"app\":\"" << escapeJSON(appTypeToString(flow->app_type))
         << "\",";
    json << "\"sni\":\"" << escapeJSON(flow->sni) << "\",";
    json << "\"packets\":" << flow->packets << ",";
    json << "\"bytes\":" << flow->bytes << ",";
    json << "\"blocked\":" << (flow->blocked ? "true" : "false") << ",";
    json << "\"ja3_hash\":\"" << escapeJSON(flow->ja3_hash) << "\",";
    json << "\"ja3_app\":\"" << escapeJSON(flow->ja3_app) << "\"";
    json << "}";
    first = false;
    flow_count++;
  }
  json << "],";

  // JA3 fingerprints
  json << "\"ja3_fingerprints\":{";
  first = true;
  int ja3_count = 0;
  for (const auto &[hash, app] : stats.detected_ja3) {
    if (ja3_count >= 20)
      break;
    if (!first)
      json << ",";
    json << "\"" << escapeJSON(hash) << "\":\""
         << escapeJSON(app.empty() ? "Unknown" : app) << "\"";
    first = false;
    ja3_count++;
  }
  json << "},";

  // GeoIP locations (unique IPs from top flows)
  json << "\"geo_locations\":[";
  first = true;
  std::unordered_set<uint32_t> seen_ips;
  int geo_count = 0;
  for (const auto *flow : sorted_flows) {
    if (geo_count >= 30)
      break;
    // Check dst_ip
    if (seen_ips.find(flow->tuple.dst_ip) == seen_ips.end()) {
      auto geo = GeoIP::lookup(flow->tuple.dst_ip);
      if (geo.country_code != "XX" && geo.country_code != "--") {
        seen_ips.insert(flow->tuple.dst_ip);
        if (!first)
          json << ",";
        json << "{\"ip\":\"" << formatIP(flow->tuple.dst_ip) << "\",\"cc\":\""
             << geo.country_code << "\",\"country\":\""
             << escapeJSON(geo.country_name) << "\",\"lat\":" << geo.latitude
             << ",\"lng\":" << geo.longitude << ",\"packets\":" << flow->packets
             << "}";
        first = false;
        geo_count++;
      }
    }
    // Check src_ip
    if (seen_ips.find(flow->tuple.src_ip) == seen_ips.end()) {
      auto geo = GeoIP::lookup(flow->tuple.src_ip);
      if (geo.country_code != "XX" && geo.country_code != "--") {
        seen_ips.insert(flow->tuple.src_ip);
        if (!first)
          json << ",";
        json << "{\"ip\":\"" << formatIP(flow->tuple.src_ip) << "\",\"cc\":\""
             << geo.country_code << "\",\"country\":\""
             << escapeJSON(geo.country_name) << "\",\"lat\":" << geo.latitude
             << ",\"lng\":" << geo.longitude << ",\"packets\":" << flow->packets
             << "}";
        first = false;
        geo_count++;
      }
    }
  }
  json << "]";

  json << "}";
  return json.str();
}

// ============================================================================
// Packet processing function (shared between PCAP and live modes)
// ============================================================================
void processPacket(const uint8_t *data, size_t length, uint32_t ts_sec,
                   uint32_t ts_usec, DashboardStats &stats,
                   DashboardBlockingRules &rules) {
  RawPacket raw;
  raw.header.ts_sec = ts_sec;
  raw.header.ts_usec = ts_usec;
  raw.header.incl_len = length;
  raw.header.orig_len = length;
  raw.data.assign(data, data + length);

  ParsedPacket parsed;
  if (!PacketParser::parse(raw, parsed))
    return;
  if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp))
    return;

  auto parseIPStr = [](const std::string &ip) -> uint32_t {
    uint32_t result = 0;
    int octet = 0, shift = 0;
    for (char c : ip) {
      if (c == '.') {
        result |= (octet << shift);
        shift += 8;
        octet = 0;
      } else if (c >= '0' && c <= '9')
        octet = octet * 10 + (c - '0');
    }
    return result | (octet << shift);
  };

  FiveTuple tuple;
  tuple.src_ip = parseIPStr(parsed.src_ip);
  tuple.dst_ip = parseIPStr(parsed.dest_ip);
  tuple.src_port = parsed.src_port;
  tuple.dst_port = parsed.dest_port;
  tuple.protocol = parsed.protocol;

  std::lock_guard<std::mutex> lock(stats.mutex);

  stats.total_packets++;
  stats.total_bytes += length;

  DashboardFlow &flow = stats.flows[tuple];
  if (flow.packets == 0)
    flow.tuple = tuple;
  flow.packets++;
  flow.bytes += length;

  // TLS SNI extraction
  if ((flow.app_type == AppType::UNKNOWN || flow.app_type == AppType::HTTPS) &&
      flow.sni.empty() && parsed.has_tcp && parsed.dest_port == 443) {
    if (parsed.payload_data && parsed.payload_length > 5) {
      auto sni =
          SNIExtractor::extract(parsed.payload_data, parsed.payload_length);
      if (sni) {
        flow.sni = *sni;
        flow.app_type = sniToAppType(*sni);
        stats.detected_snis[*sni] = flow.app_type;
      }
      // JA3 fingerprinting
      if (flow.ja3_hash.empty()) {
        auto ja3 = JA3Fingerprint::fingerprint(parsed.payload_data,
                                               parsed.payload_length);
        if (ja3) {
          flow.ja3_hash = ja3->ja3_hash;
          flow.ja3_app = JA3Fingerprint::lookupJA3(ja3->ja3_hash);
          stats.detected_ja3[ja3->ja3_hash] = flow.ja3_app;
        }
      }
    }
  }

  // HTTP Host extraction
  if ((flow.app_type == AppType::UNKNOWN || flow.app_type == AppType::HTTP) &&
      flow.sni.empty() && parsed.has_tcp && parsed.dest_port == 80) {
    if (parsed.payload_data && parsed.payload_length > 4) {
      auto host = HTTPHostExtractor::extract(parsed.payload_data,
                                             parsed.payload_length);
      if (host) {
        flow.sni = *host;
        flow.app_type = sniToAppType(*host);
        stats.detected_snis[*host] = flow.app_type;
      }
    }
  }

  // DNS query extraction
  if (parsed.has_udp && (parsed.dest_port == 53 || parsed.src_port == 53)) {
    flow.app_type = AppType::DNS;
    if (parsed.dest_port == 53 && parsed.payload_data &&
        parsed.payload_length > 12) {
      auto dns_domain = DNSExtractor::extractQuery(parsed.payload_data,
                                                   parsed.payload_length);
      if (dns_domain) {
        flow.sni = *dns_domain;
        stats.detected_snis[*dns_domain] = AppType::DNS;
        stats.dns_ip_to_domain[parsed.dest_ip] = *dns_domain;
      }
    }
  }

  // QUIC SNI extraction
  if (flow.app_type == AppType::UNKNOWN && flow.sni.empty() && parsed.has_udp &&
      parsed.dest_port == 443) {
    if (parsed.payload_data && parsed.payload_length > 5) {
      auto quic_sni =
          QUICSNIExtractor::extract(parsed.payload_data, parsed.payload_length);
      if (quic_sni) {
        flow.sni = *quic_sni;
        flow.app_type = sniToAppType(*quic_sni);
        stats.detected_snis[*quic_sni] = flow.app_type;
      } else {
        flow.app_type = AppType::QUIC;
      }
    }
  }

  // Feed to IDS
  stats.ids.processPacket(tuple.src_ip, tuple.dst_ip, tuple.dst_port,
                          parsed.has_tcp ? parsed.tcp_flags : 0,
                          parsed.timestamp_sec);

  // DNS correlation fallback
  if (flow.app_type == AppType::UNKNOWN || flow.app_type == AppType::HTTPS ||
      flow.app_type == AppType::HTTP) {
    auto it = stats.dns_ip_to_domain.find(parsed.dest_ip);
    if (it != stats.dns_ip_to_domain.end() && flow.sni.empty()) {
      flow.sni = it->second;
      flow.app_type = sniToAppType(it->second);
    }
  }

  // Port-based fallback
  if (flow.app_type == AppType::UNKNOWN) {
    if (parsed.dest_port == 443)
      flow.app_type = AppType::HTTPS;
    else if (parsed.dest_port == 80)
      flow.app_type = AppType::HTTP;
  }

  // Blocking
  if (!flow.blocked) {
    flow.blocked = rules.isBlocked(tuple.src_ip, flow.app_type, flow.sni);
  }

  stats.app_counts[flow.app_type]++;
  if (flow.blocked)
    stats.dropped++;
  else
    stats.forwarded++;
}

// ============================================================================
// Usage
// ============================================================================
void printUsage(const char *prog) {
  std::cout << R"(
NetSpectre - Dashboard Mode
============================

Usage:
  )" << prog << R"( --pcap <input.pcap> [options]   Process a PCAP file
  sudo )" << prog
            << R"( --interface <name> [options]  Live capture

Options:
  --pcap <file>          Input PCAP file to analyze
  --interface <name>     Live capture interface (requires sudo)
  --port <port>          Dashboard HTTP port (default: 8080)
  --block-app <app>      Block application
  --block-domain <dom>   Block domain (substring match)
  --block-ip <ip>        Block IP address

Open http://localhost:<port> in your browser to view the dashboard.

Example:
  )" << prog << R"( --pcap capture.pcap --port 8080 --block-app YouTube
)";
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char *argv[]) {
  std::signal(SIGINT, signalHandler);
  std::signal(SIGTERM, signalHandler);

  std::string pcap_file;
  std::string interface;
  int port = 8080;
  DashboardBlockingRules rules;

  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "--help" || arg == "-h") {
      printUsage(argv[0]);
      return 0;
    } else if (arg == "--pcap" && i + 1 < argc)
      pcap_file = argv[++i];
    else if (arg == "--interface" && i + 1 < argc)
      interface = argv[++i];
    else if (arg == "--port" && i + 1 < argc)
      port = std::stoi(argv[++i]);
    else if (arg == "--block-ip" && i + 1 < argc)
      rules.blockIP(argv[++i]);
    else if (arg == "--block-app" && i + 1 < argc)
      rules.blockApp(argv[++i]);
    else if (arg == "--block-domain" && i + 1 < argc)
      rules.blockDomain(argv[++i]);
  }

  if (pcap_file.empty() && interface.empty()) {
    std::cerr << "Error: Must specify --pcap <file> or --interface <name>\n";
    printUsage(argv[0]);
    return 1;
  }

  std::cout << "\n";
  std::cout
      << "╔══════════════════════════════════════════════════════════════╗\n";
  std::cout
      << "║            NETSPECTRE v2.0 — DASHBOARD MODE                 ║\n";
  std::cout
      << "╚══════════════════════════════════════════════════════════════╝\n\n";

  // Shared stats
  DashboardStats stats;

  // Start dashboard server
  DashboardServer server(port);
  server.setStatsProvider(
      [&stats]() -> std::string { return statsToJSON(stats); });

  if (!server.start()) {
    std::cerr << "Error: Failed to start dashboard server on port " << port
              << "\n";
    return 1;
  }

  std::cout << "[DPI] Open http://localhost:" << port << " in your browser\n\n";

  if (!pcap_file.empty()) {
    // PCAP file mode
    std::cout << "[DPI] Processing PCAP file: " << pcap_file << "\n";

    PcapReader reader;
    if (!reader.open(pcap_file)) {
      std::cerr << "Error: Cannot open PCAP file: " << pcap_file << "\n";
      return 1;
    }

    RawPacket raw;
    while (reader.readNextPacket(raw) && g_running.load()) {
      processPacket(raw.data.data(), raw.data.size(), raw.header.ts_sec,
                    raw.header.ts_usec, stats, rules);
    }
    reader.close();

    {
      std::lock_guard<std::mutex> lock(stats.mutex);
      stats.processing_complete = true;
    }

    std::cout << "[DPI] PCAP processing complete. " << stats.total_packets
              << " packets analyzed.\n";
    std::cout << "[DPI] Dashboard is serving results. Press Ctrl+C to exit.\n";

    // Keep server running until Ctrl+C
    while (g_running.load()) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }

  } else {
    // Live capture mode
    std::cout << "[DPI] Starting live capture on interface: "
              << interface << "\n";

    LiveCapture capture;
    g_live_capture = &capture;

    if (!capture.start(interface)) {
      std::cerr << "Error: Failed to start capture. Try running with sudo.\n";
      return 1;
    }

    capture.processPackets([&](const uint8_t *data, size_t length,
                               uint32_t ts_sec, uint32_t ts_usec) {
      processPacket(data, length, ts_sec, ts_usec, stats, rules);
    });

    g_live_capture = nullptr;
  }

  server.stop();
  std::cout << "\n[DPI] Dashboard server stopped.\n";
  return 0;
}
