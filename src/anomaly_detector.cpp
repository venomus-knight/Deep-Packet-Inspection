#include "anomaly_detector.h"
#include <sstream>

namespace DPI {

// ============================================================================
// Constructor
// ============================================================================
AnomalyDetector::AnomalyDetector(const AnomalyConfig &config)
    : config_(config) {}

// ============================================================================
// IP to string
// ============================================================================
std::string AnomalyDetector::ipToString(uint32_t ip) {
  std::ostringstream ss;
  ss << (ip & 0xFF) << "." << ((ip >> 8) & 0xFF) << "." << ((ip >> 16) & 0xFF)
     << "." << ((ip >> 24) & 0xFF);
  return ss.str();
}

std::string AnomalyDetector::alertTypeToString(AlertType type) {
  switch (type) {
  case AlertType::PORT_SCAN:
    return "PORT_SCAN";
  case AlertType::SYN_FLOOD:
    return "SYN_FLOOD";
  default:
    return "UNKNOWN";
  }
}

std::string AnomalyDetector::severityToString(uint32_t severity) {
  switch (severity) {
  case 1:
    return "LOW";
  case 2:
    return "MEDIUM";
  case 3:
    return "HIGH";
  case 4:
    return "CRITICAL";
  default:
    return "UNKNOWN";
  }
}

// ============================================================================
// Process a packet — runs both detectors
// ============================================================================
void AnomalyDetector::processPacket(uint32_t src_ip, uint32_t dst_ip,
                                    uint16_t dst_port, uint8_t tcp_flags,
                                    uint32_t timestamp_sec) {
  std::lock_guard<std::mutex> lock(mutex_);

  // Port scan detection (any protocol)
  detectPortScan(src_ip, dst_port, timestamp_sec);

  // SYN flood detection (TCP only — check if SYN flag is set)
  if (tcp_flags != 0) {
    detectSynFlood(src_ip, dst_ip, tcp_flags, timestamp_sec);
  }
}

// ============================================================================
// Port Scan Detection
// ============================================================================
//
// Tracks unique destination ports per source IP within a sliding time window.
//
// Example attack pattern (nmap scan):
//   192.168.1.100 -> 10.0.0.1:22    (SSH)
//   192.168.1.100 -> 10.0.0.1:80    (HTTP)
//   192.168.1.100 -> 10.0.0.1:443   (HTTPS)
//   192.168.1.100 -> 10.0.0.1:3389  (RDP)
//   ... 20+ unique ports in 60 seconds = ALERT!
//
void AnomalyDetector::detectPortScan(uint32_t src_ip, uint16_t dst_port,
                                     uint32_t timestamp) {
  auto &tracker = port_scan_trackers_[src_ip];

  // Reset window if expired
  if (tracker.window_start == 0) {
    tracker.window_start = timestamp;
  } else if (timestamp - tracker.window_start > config_.port_scan_window_sec) {
    tracker.unique_ports.clear();
    tracker.window_start = timestamp;
    tracker.alerted = false;
  }

  // Track this port
  tracker.unique_ports.insert(dst_port);

  // Check threshold
  if (!tracker.alerted &&
      tracker.unique_ports.size() >= config_.port_scan_threshold) {

    std::string src_str = ipToString(src_ip);
    uint32_t port_count = static_cast<uint32_t>(tracker.unique_ports.size());

    // Severity based on port count
    uint32_t severity = 2; // MEDIUM
    if (port_count >= 100)
      severity = 4; // CRITICAL
    else if (port_count >= 50)
      severity = 3; // HIGH

    std::ostringstream desc;
    desc << "Port scan detected from " << src_str << ": " << port_count
         << " unique ports in " << config_.port_scan_window_sec << "s window";

    addAlert(AlertType::PORT_SCAN, src_ip, 0, desc.str(), timestamp, severity);
    tracker.alerted = true;
  }
}

// ============================================================================
// SYN Flood Detection
// ============================================================================
//
// Tracks SYN and SYN-ACK counts per destination IP.
// A normal TCP handshake: SYN -> SYN-ACK -> ACK
// In a SYN flood: many SYNs, few/no SYN-ACKs (half-open connections)
//
// Detection: if SYN_count > threshold AND SYN/SYN-ACK ratio > ratio_threshold
//
// Example attack pattern:
//   10.0.0.1 receives 500 SYNs but only 10 SYN-ACKs in 10 seconds
//   Ratio = 50:1 (>> 5:1 threshold) = ALERT!
//
void AnomalyDetector::detectSynFlood(uint32_t src_ip, uint32_t dst_ip,
                                     uint8_t tcp_flags, uint32_t timestamp) {
  constexpr uint8_t SYN = 0x02;
  constexpr uint8_t ACK = 0x10;

  bool is_syn = (tcp_flags & SYN) && !(tcp_flags & ACK);    // Pure SYN
  bool is_syn_ack = (tcp_flags & SYN) && (tcp_flags & ACK); // SYN-ACK

  if (!is_syn && !is_syn_ack)
    return;

  // For SYN: track against the destination (the target)
  // For SYN-ACK: track against the source (the target responding)
  uint32_t target_ip = is_syn ? dst_ip : src_ip;

  auto &tracker = syn_flood_trackers_[target_ip];

  // Reset window if expired
  if (tracker.window_start == 0) {
    tracker.window_start = timestamp;
  } else if (timestamp - tracker.window_start > config_.syn_flood_window_sec) {
    tracker.syn_count = 0;
    tracker.syn_ack_count = 0;
    tracker.window_start = timestamp;
    tracker.alerted = false;
  }

  // Count
  if (is_syn) {
    tracker.syn_count++;
  } else if (is_syn_ack) {
    tracker.syn_ack_count++;
  }

  // Check threshold
  if (!tracker.alerted && tracker.syn_count >= config_.syn_flood_threshold) {

    // Calculate ratio
    double ratio =
        (tracker.syn_ack_count > 0)
            ? static_cast<double>(tracker.syn_count) / tracker.syn_ack_count
            : static_cast<double>(
                  tracker.syn_count); // No SYN-ACKs = worst case

    if (ratio >= config_.syn_flood_ratio) {
      std::string target_str = ipToString(target_ip);

      // Severity based on SYN count
      uint32_t severity = 3; // HIGH
      if (tracker.syn_count >= 1000)
        severity = 4; // CRITICAL

      std::ostringstream desc;
      desc << "SYN flood targeting " << target_str << ": " << tracker.syn_count
           << " SYNs, " << tracker.syn_ack_count << " SYN-ACKs"
           << " (ratio " << std::fixed;
      desc.precision(1);
      desc << ratio << ":1) in " << config_.syn_flood_window_sec << "s window";

      addAlert(AlertType::SYN_FLOOD, 0, target_ip, desc.str(), timestamp,
               severity);
      tracker.alerted = true;
    }
  }
}

// ============================================================================
// Alert Management
// ============================================================================
void AnomalyDetector::addAlert(AlertType type, uint32_t src_ip,
                               uint32_t target_ip,
                               const std::string &description,
                               uint32_t timestamp, uint32_t severity) {
  Alert alert;
  alert.type = type;
  alert.source_ip = src_ip;
  alert.target_ip = target_ip;
  alert.description = description;
  alert.timestamp = timestamp;
  alert.severity = severity;

  pending_alerts_.push_back(alert);
  total_alert_count_++;
}

std::vector<Alert> AnomalyDetector::getAlerts() {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<Alert> alerts = std::move(pending_alerts_);
  pending_alerts_.clear();
  return alerts;
}

std::vector<Alert> AnomalyDetector::peekAlerts() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return pending_alerts_;
}

size_t AnomalyDetector::totalAlerts() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return total_alert_count_;
}

} // namespace DPI
