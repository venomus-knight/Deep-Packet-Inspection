// DPI Engine - Live Capture Mode
// Captures packets from a network interface in real-time and applies DPI
// analysis
//
// Usage: sudo ./dpi_live [--interface en0] [--duration 30] [--filter "tcp"]
//        [--block-app YouTube] [--block-domain facebook.com]

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "anomaly_detector.h"
#include "ja3_fingerprint.h"
#include "live_capture.h"
#include "packet_parser.h"
#include "pcap_reader.h"
#include "sni_extractor.h"
#include "types.h"

using namespace PacketAnalyzer;
using namespace DPI;

// ============================================================================
// Global signal handler for Ctrl+C
// ============================================================================
static std::atomic<bool> g_running{true};
static LiveCapture *g_capture = nullptr;

void signalHandler(int signum) {
  (void)signum;
  std::cout << "\n[DPI] Caught interrupt signal, shutting down...\n";
  g_running.store(false);
  if (g_capture) {
    g_capture->stop();
  }
}

// ============================================================================
// Live Flow Tracking
// ============================================================================
struct LiveFlow {
  FiveTuple tuple;
  AppType app_type = AppType::UNKNOWN;
  std::string sni;
  std::string ja3_hash;
  std::string ja3_app;
  uint64_t packets = 0;
  uint64_t bytes = 0;
  bool blocked = false;
};

// ============================================================================
// Blocking Rules (same as main_working.cpp)
// ============================================================================
class LiveBlockingRules {
public:
  std::unordered_set<uint32_t> blocked_ips;
  std::unordered_set<AppType> blocked_apps;
  std::vector<std::string> blocked_domains;

  void blockIP(const std::string &ip) {
    uint32_t addr = parseIP(ip);
    blocked_ips.insert(addr);
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
    std::cerr << "[Rules] Unknown app: " << app << "\n";
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
// Statistics display
// ============================================================================
struct LiveStats {
  std::mutex mutex;
  uint64_t total_packets = 0;
  uint64_t total_bytes = 0;
  uint64_t forwarded = 0;
  uint64_t dropped = 0;
  std::unordered_map<AppType, uint64_t> app_counts;
  std::unordered_map<std::string, AppType> detected_snis;
  std::unordered_map<std::string, std::string> detected_ja3; // hash -> app
  AnomalyDetector ids;
  std::unordered_map<FiveTuple, LiveFlow, FiveTupleHash> flows;
  std::unordered_map<std::string, std::string> dns_ip_to_domain;
};

void printLiveStats(const LiveStats &stats) {
  // Move cursor up and clear for "live" display effect
  std::cout << "\033[2J\033[H"; // Clear screen, move to top

  std::cout
      << "╔══════════════════════════════════════════════════════════════╗\n";
  std::cout
      << "║              DPI ENGINE v2.0 — LIVE CAPTURE                 ║\n";
  std::cout
      << "╠══════════════════════════════════════════════════════════════╣\n";
  std::cout << "║ Total Packets:  " << std::setw(12) << stats.total_packets
            << "                                ║\n";
  std::cout << "║ Total Bytes:    " << std::setw(12) << stats.total_bytes
            << "                                ║\n";
  std::cout << "║ Forwarded:      " << std::setw(12) << stats.forwarded
            << "                                ║\n";
  std::cout << "║ Dropped:        " << std::setw(12) << stats.dropped
            << "                                ║\n";
  std::cout << "║ Active Flows:   " << std::setw(12) << stats.flows.size()
            << "                                ║\n";
  std::cout
      << "╠══════════════════════════════════════════════════════════════╣\n";
  std::cout
      << "║                   APPLICATION BREAKDOWN                     ║\n";
  std::cout
      << "╠══════════════════════════════════════════════════════════════╣\n";

  // Sort by count
  std::vector<std::pair<AppType, uint64_t>> sorted_apps(
      stats.app_counts.begin(), stats.app_counts.end());
  std::sort(sorted_apps.begin(), sorted_apps.end(),
            [](const auto &a, const auto &b) { return a.second > b.second; });

  for (const auto &[app, count] : sorted_apps) {
    if (stats.total_packets == 0)
      continue;
    double pct = 100.0 * count / stats.total_packets;
    int bar_len = static_cast<int>(pct / 5);
    std::string bar(bar_len, '#');

    std::cout << "║ " << std::setw(15) << std::left << appTypeToString(app)
              << std::setw(8) << std::right << count << " " << std::setw(5)
              << std::fixed << std::setprecision(1) << pct << "% "
              << std::setw(20) << std::left << bar << "  ║\n";
  }

  std::cout
      << "╠══════════════════════════════════════════════════════════════╣\n";
  std::cout
      << "║                  DETECTED DOMAINS (SNIs)                    ║\n";
  std::cout
      << "╠══════════════════════════════════════════════════════════════╣\n";

  int sni_count = 0;
  for (const auto &[sni, app] : stats.detected_snis) {
    if (sni_count >= 10) {
      std::cout << "║   ... and " << (stats.detected_snis.size() - 10)
                << " more                                          ║\n";
      break;
    }
    std::string display_sni =
        sni.length() > 35 ? sni.substr(0, 35) + "..." : sni;
    std::cout << "║   " << std::setw(40) << std::left << display_sni
              << std::setw(15) << appTypeToString(app) << "  ║\n";
    sni_count++;
  }

  std::cout
      << "╠══════════════════════════════════════════════════════════════╣\n";
  std::cout
      << "║                ANOMALY DETECTION (IDS)                      ║\n";
  std::cout
      << "╠══════════════════════════════════════════════════════════════╣\n";

  auto alerts = stats.ids.peekAlerts();
  if (alerts.empty()) {
    std::cout
        << "║   No anomalies detected.                                     ║\n";
  } else {
    int alert_count = 0;
    for (const auto &alert : alerts) {
      if (alert_count >= 5) {
        std::cout << "║   ... and " << (alerts.size() - 5)
                  << " more                                          ║\n";
        break;
      }
      std::string display =
          "[" + AnomalyDetector::severityToString(alert.severity) + "] " +
          AnomalyDetector::alertTypeToString(alert.type);
      if (display.length() > 55)
        display = display.substr(0, 52) + "...";
      std::cout << "║   " << std::setw(55) << std::left << display << "  ║\n";
      alert_count++;
    }
  }

  std::cout
      << "╚══════════════════════════════════════════════════════════════╝\n";
  std::cout << "\nPress Ctrl+C to stop capture...\n";
}

// ============================================================================
// Usage
// ============================================================================
void printUsage(const char *prog) {
  std::cout << R"(
DPI Engine - Live Capture Mode
==============================

Usage: sudo )"
            << prog << R"( [options]

Options:
  --interface <name>     Network interface (default: first available)
  --duration <secs>      Capture duration in seconds (default: unlimited)
  --filter <bpf>         BPF filter expression (e.g., "tcp port 443")
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)
  --list-interfaces      List available network interfaces and exit

Example:
  sudo )" << prog
            << R"( --interface en0 --duration 30 --block-app YouTube
)";
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char *argv[]) {
  // Install signal handler
  std::signal(SIGINT, signalHandler);
  std::signal(SIGTERM, signalHandler);

  std::string interface;
  std::string filter;
  int duration = 0; // 0 = unlimited
  LiveBlockingRules rules;

  // Parse arguments
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "--help" || arg == "-h") {
      printUsage(argv[0]);
      return 0;
    } else if (arg == "--list-interfaces") {
      auto ifaces = LiveCapture::listInterfaces();
      std::cout << "Available network interfaces:\n";
      for (const auto &iface : ifaces) {
        std::cout << "  - " << iface.name << " : " << iface.description << "\n";
      }
      return 0;
    } else if (arg == "--interface" && i + 1 < argc) {
      interface = argv[++i];
    } else if (arg == "--duration" && i + 1 < argc) {
      duration = std::stoi(argv[++i]);
    } else if (arg == "--filter" && i + 1 < argc) {
      filter = argv[++i];
    } else if (arg == "--block-ip" && i + 1 < argc) {
      rules.blockIP(argv[++i]);
    } else if (arg == "--block-app" && i + 1 < argc) {
      rules.blockApp(argv[++i]);
    } else if (arg == "--block-domain" && i + 1 < argc) {
      rules.blockDomain(argv[++i]);
    }
  }

  // If no interface specified, use the first available
  if (interface.empty()) {
    auto ifaces = LiveCapture::listInterfaces();
    if (ifaces.empty()) {
      std::cerr
          << "Error: No network interfaces found. Try running with sudo.\n";
      return 1;
    }
    // Skip loopback, prefer en0 or similar
    for (const auto &iface : ifaces) {
      if (iface.name != "lo" && iface.name != "lo0") {
        interface = iface.name;
        break;
      }
    }
    if (interface.empty()) {
      interface = ifaces[0].name;
    }
  }

  std::cout << "\n";
  std::cout
      << "╔══════════════════════════════════════════════════════════════╗\n";
  std::cout
      << "║              DPI ENGINE v2.0 — LIVE CAPTURE                 ║\n";
  std::cout
      << "╚══════════════════════════════════════════════════════════════╝\n\n";

  // Start capture
  LiveCapture capture;
  g_capture = &capture;

  if (!capture.start(interface, filter)) {
    std::cerr << "Error: Failed to start capture. Try running with sudo.\n";
    return 1;
  }

  // Shared statistics
  LiveStats stats;

  // Start a timer thread for periodic display + duration limit
  auto start_time = std::chrono::steady_clock::now();

  std::thread display_thread([&]() {
    while (g_running.load()) {
      std::this_thread::sleep_for(std::chrono::seconds(2));
      if (!g_running.load())
        break;

      std::lock_guard<std::mutex> lock(stats.mutex);
      printLiveStats(stats);

      // Check duration
      if (duration > 0) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::steady_clock::now() - start_time)
                           .count();
        if (elapsed >= duration) {
          std::cout << "\n[DPI] Duration limit reached (" << duration << "s)\n";
          g_running.store(false);
          capture.stop();
          break;
        }
      }
    }
  });

  // Process packets
  capture.processPackets([&](const uint8_t *data, size_t length,
                             uint32_t ts_sec, uint32_t ts_usec) {
    // Wrap as RawPacket for the parser
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

    // Create five-tuple
    auto parseIP = [](const std::string &ip) -> uint32_t {
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
    tuple.src_ip = parseIP(parsed.src_ip);
    tuple.dst_ip = parseIP(parsed.dest_ip);
    tuple.src_port = parsed.src_port;
    tuple.dst_port = parsed.dest_port;
    tuple.protocol = parsed.protocol;

    std::lock_guard<std::mutex> lock(stats.mutex);

    stats.total_packets++;
    stats.total_bytes += length;

    // Get or create flow
    LiveFlow &flow = stats.flows[tuple];
    if (flow.packets == 0) {
      flow.tuple = tuple;
    }
    flow.packets++;
    flow.bytes += length;

    // TLS SNI extraction
    if ((flow.app_type == AppType::UNKNOWN ||
         flow.app_type == AppType::HTTPS) &&
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

    // QUIC SNI extraction (UDP port 443)
    if (flow.app_type == AppType::UNKNOWN && flow.sni.empty() &&
        parsed.has_udp && parsed.dest_port == 443) {
      if (parsed.payload_data && parsed.payload_length > 5) {
        auto quic_sni = QUICSNIExtractor::extract(parsed.payload_data,
                                                  parsed.payload_length);
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

    // Check blocking rules
    if (!flow.blocked) {
      flow.blocked = rules.isBlocked(tuple.src_ip, flow.app_type, flow.sni);
    }

    // Update stats
    stats.app_counts[flow.app_type]++;
    if (flow.blocked) {
      stats.dropped++;
    } else {
      stats.forwarded++;
    }
  });

  display_thread.join();
  g_capture = nullptr;

  // Final report
  std::lock_guard<std::mutex> lock(stats.mutex);
  printLiveStats(stats);

  auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                     std::chrono::steady_clock::now() - start_time)
                     .count();
  std::cout << "\n[DPI] Capture completed. Duration: " << elapsed
            << " seconds\n";
  std::cout << "[DPI] Total packets processed: " << stats.total_packets << "\n";

  return 0;
}
