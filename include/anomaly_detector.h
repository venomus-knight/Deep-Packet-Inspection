#ifndef ANOMALY_DETECTOR_H
#define ANOMALY_DETECTOR_H

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace DPI {

// ============================================================================
// Anomaly Detection — Intrusion Detection System (IDS)
// ============================================================================
//
// Detects two key attack patterns in real-time:
//
// 1. PORT SCAN
//    A single source IP connects to many unique destination ports.
//    Attackers scan ports to find open services (e.g., nmap -sS).
//    Detection: track unique dst ports per src IP in a time window.
//
// 2. SYN FLOOD (DoS/DDoS)
//    Attacker sends massive SYN packets without completing handshake.
//    This exhausts the target's connection table (half-open connections).
//    Detection: high SYN count with low SYN-ACK ratio per dst IP.
//
// ============================================================================

enum class AlertType { PORT_SCAN, SYN_FLOOD };

struct Alert {
  AlertType type;
  uint32_t source_ip;      // Who is doing it
  uint32_t target_ip;      // Who is being targeted (for SYN flood)
  std::string description; // Human-readable alert message
  uint32_t timestamp;      // When it was detected (epoch seconds)
  uint32_t severity;       // 1=low, 2=medium, 3=high, 4=critical
};

// Configuration thresholds
struct AnomalyConfig {
  // Port scan detection
  uint16_t port_scan_threshold = 20;  // Unique ports to trigger alert
  uint32_t port_scan_window_sec = 60; // Time window in seconds

  // SYN flood detection
  uint32_t syn_flood_threshold = 100; // SYN count to trigger alert
  double syn_flood_ratio = 5.0;       // SYN/SYN-ACK ratio threshold
  uint32_t syn_flood_window_sec = 10; // Time window in seconds
};

class AnomalyDetector {
public:
  explicit AnomalyDetector(const AnomalyConfig &config = AnomalyConfig{});

  // Feed a packet to the detector
  // tcp_flags: raw TCP flags byte (0 for non-TCP packets)
  void processPacket(uint32_t src_ip, uint32_t dst_ip, uint16_t dst_port,
                     uint8_t tcp_flags, uint32_t timestamp_sec);

  // Get and clear all pending alerts
  std::vector<Alert> getAlerts();

  // Get all alerts without clearing
  std::vector<Alert> peekAlerts() const;

  // Total alerts generated since creation
  size_t totalAlerts() const;

  // Format IP to string
  static std::string ipToString(uint32_t ip);

  // Format alert type to string
  static std::string alertTypeToString(AlertType type);

  // Format severity to string
  static std::string severityToString(uint32_t severity);

private:
  AnomalyConfig config_;

  // Port scan tracking: src_ip -> tracker
  struct PortScanTracker {
    std::unordered_set<uint16_t> unique_ports;
    uint32_t window_start = 0;
    bool alerted = false; // Only alert once per window
  };
  std::unordered_map<uint32_t, PortScanTracker> port_scan_trackers_;

  // SYN flood tracking: dst_ip -> tracker
  struct SynFloodTracker {
    uint32_t syn_count = 0;
    uint32_t syn_ack_count = 0;
    uint32_t window_start = 0;
    bool alerted = false;
  };
  std::unordered_map<uint32_t, SynFloodTracker> syn_flood_trackers_;

  // Pending alerts
  std::vector<Alert> pending_alerts_;
  size_t total_alert_count_ = 0;

  // Mutex for thread safety
  mutable std::mutex mutex_;

  // Internal detection methods
  void detectPortScan(uint32_t src_ip, uint16_t dst_port, uint32_t timestamp);
  void detectSynFlood(uint32_t src_ip, uint32_t dst_ip, uint8_t tcp_flags,
                      uint32_t timestamp);
  void addAlert(AlertType type, uint32_t src_ip, uint32_t target_ip,
                const std::string &description, uint32_t timestamp,
                uint32_t severity);
};

} // namespace DPI

#endif // ANOMALY_DETECTOR_H
