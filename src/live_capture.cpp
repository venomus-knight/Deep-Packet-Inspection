#include "live_capture.h"
#include <cstring>
#include <iostream>
#include <pcap/pcap.h>

namespace DPI {

LiveCapture::LiveCapture() = default;

LiveCapture::~LiveCapture() { stop(); }

std::vector<InterfaceInfo> LiveCapture::listInterfaces() {
  std::vector<InterfaceInfo> interfaces;

  pcap_if_t *alldevs = nullptr;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    std::cerr << "[LiveCapture] Error finding interfaces: " << errbuf << "\n";
    return interfaces;
  }

  for (pcap_if_t *dev = alldevs; dev != nullptr; dev = dev->next) {
    InterfaceInfo info;
    info.name = dev->name;
    info.description = dev->description ? dev->description : "(no description)";
    interfaces.push_back(info);
  }

  pcap_freealldevs(alldevs);
  return interfaces;
}

bool LiveCapture::start(const std::string &interface, const std::string &filter,
                        int snaplen) {
  char errbuf[PCAP_ERRBUF_SIZE];

  // Open the interface for live capture
  handle_ =
      pcap_open_live(interface.c_str(), snaplen,
                     1,   // promiscuous mode
                     100, // read timeout in ms (allows periodic stop checks)
                     errbuf);

  if (handle_ == nullptr) {
    std::cerr << "[LiveCapture] Error opening " << interface << ": " << errbuf
              << "\n";
    return false;
  }

  // Apply BPF filter if specified
  if (!filter.empty()) {
    struct bpf_program fp;
    if (pcap_compile(handle_, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) ==
        -1) {
      std::cerr << "[LiveCapture] Error compiling filter: "
                << pcap_geterr(handle_) << "\n";
      pcap_close(handle_);
      handle_ = nullptr;
      return false;
    }
    if (pcap_setfilter(handle_, &fp) == -1) {
      std::cerr << "[LiveCapture] Error setting filter: "
                << pcap_geterr(handle_) << "\n";
      pcap_freecode(&fp);
      pcap_close(handle_);
      handle_ = nullptr;
      return false;
    }
    pcap_freecode(&fp);
  }

  capturing_.store(true);
  std::cout << "[LiveCapture] Capturing on interface: " << interface << "\n";
  if (!filter.empty()) {
    std::cout << "[LiveCapture] Filter: " << filter << "\n";
  }

  return true;
}

void LiveCapture::stop() {
  capturing_.store(false);
  if (handle_ != nullptr) {
    pcap_breakloop(handle_);
  }
}

uint64_t LiveCapture::processPackets(PacketCallback callback) {
  if (handle_ == nullptr)
    return 0;

  user_callback_ = std::move(callback);
  packet_count_ = 0;

  // Use pcap_loop — will call our static callback for each packet
  // cnt = -1 means loop until error or pcap_breakloop
  while (capturing_.load()) {
    int ret = pcap_dispatch(handle_, 100, pcapCallback,
                            reinterpret_cast<unsigned char *>(this));
    if (ret == PCAP_ERROR_BREAK || ret == PCAP_ERROR) {
      break;
    }
  }

  // Cleanup
  pcap_close(handle_);
  handle_ = nullptr;

  return packet_count_;
}

void LiveCapture::pcapCallback(unsigned char *user,
                               const struct pcap_pkthdr *header,
                               const unsigned char *data) {
  auto *self = reinterpret_cast<LiveCapture *>(user);

  if (!self->capturing_.load())
    return;

  self->packet_count_++;

  if (self->user_callback_) {
    self->user_callback_(data, header->caplen,
                         static_cast<uint32_t>(header->ts.tv_sec),
                         static_cast<uint32_t>(header->ts.tv_usec));
  }
}

int LiveCapture::dataLinkType() const {
  if (handle_ == nullptr)
    return -1;
  return pcap_datalink(handle_);
}

} // namespace DPI
