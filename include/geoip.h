#ifndef GEOIP_H
#define GEOIP_H

#include <cstdint>
#include <string>
#include <vector>

namespace DPI {

// ============================================================================
// GeoIP - Lightweight IP geolocation using built-in IP range database
// ============================================================================
// Maps IP addresses to country codes and approximate lat/lng for map display.
// No external database files needed — common ranges are embedded.

struct GeoLocation {
  std::string country_code; // ISO 3166-1 alpha-2 (e.g., "US", "DE")
  std::string country_name; // Full name (e.g., "United States")
  double latitude;
  double longitude;
};

class GeoIP {
public:
  // Look up an IP address (in host byte order, little-endian as stored)
  static GeoLocation lookup(uint32_t ip);

  // Look up from IP string "A.B.C.D"
  static GeoLocation lookup(const std::string &ip_str);

  // Convert IP uint32 to string
  static std::string ipToString(uint32_t ip);

private:
  struct IPRange {
    uint32_t start;
    uint32_t end;
    const char *country_code;
    const char *country_name;
    double lat;
    double lng;
  };

  static const std::vector<IPRange> &getDatabase();
};

} // namespace DPI

#endif // GEOIP_H
