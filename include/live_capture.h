#ifndef LIVE_CAPTURE_H
#define LIVE_CAPTURE_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

// Forward declare pcap types to avoid including pcap.h in the header
struct pcap;
typedef struct pcap pcap_t;
struct pcap_pkthdr;

namespace DPI {

// Information about a network interface
struct InterfaceInfo {
  std::string name;
  std::string description;
};

// Callback signature for packet processing
// Parameters: raw packet data, length, timestamp seconds, timestamp
// microseconds
using PacketCallback = std::function<void(const uint8_t *data, size_t length,
                                          uint32_t ts_sec, uint32_t ts_usec)>;

// ============================================================================
// LiveCapture - Real-time packet capture using libpcap
// ============================================================================
class LiveCapture {
public:
  LiveCapture();
  ~LiveCapture();

  // List available network interfaces
  static std::vector<InterfaceInfo> listInterfaces();

  // Start capturing from an interface
  // interface: network interface name (e.g., "en0", "eth0")
  // filter: BPF filter string (e.g., "tcp port 443", "" for all)
  // snaplen: max bytes to capture per packet (default 65535)
  // Returns true if capture started successfully
  bool start(const std::string &interface, const std::string &filter = "",
             int snaplen = 65535);

  // Stop capturing (can be called from another thread or signal handler)
  void stop();

  // Process packets in a loop (blocking call)
  // Calls callback for each packet until stop() is called
  // Returns total packets processed
  uint64_t processPackets(PacketCallback callback);

  // Check if currently capturing
  bool isCapturing() const { return capturing_.load(); }

  // Get the data link type (usually DLT_EN10MB = 1 for Ethernet)
  int dataLinkType() const;

private:
  pcap_t *handle_ = nullptr;
  std::atomic<bool> capturing_{false};

  // Static callback for pcap_loop, forwards to instance callback
  static void pcapCallback(unsigned char *user,
                           const struct pcap_pkthdr *header,
                           const unsigned char *data);

  // Instance-level callback storage
  PacketCallback user_callback_;
  uint64_t packet_count_ = 0;
};

} // namespace DPI

#endif // LIVE_CAPTURE_H
