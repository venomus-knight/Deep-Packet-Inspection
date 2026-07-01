#include "geoip.h"
#include <algorithm>
#include <sstream>

namespace DPI {

// ============================================================================
// IP conversion helpers
// ============================================================================
static uint32_t ipToNetworkOrder(uint32_t ip_le) {
  // Our IPs are stored in little-endian (as parsed from packet).
  // Convert to big-endian (network order) for range comparison.
  return ((ip_le & 0xFF) << 24) | (((ip_le >> 8) & 0xFF) << 16) |
         (((ip_le >> 16) & 0xFF) << 8) | ((ip_le >> 24) & 0xFF);
}

static uint32_t makeIP(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
  return (static_cast<uint32_t>(a) << 24) | (static_cast<uint32_t>(b) << 16) |
         (static_cast<uint32_t>(c) << 8) | static_cast<uint32_t>(d);
}

std::string GeoIP::ipToString(uint32_t ip) {
  std::ostringstream ss;
  ss << (ip & 0xFF) << "." << ((ip >> 8) & 0xFF) << "." << ((ip >> 16) & 0xFF)
     << "." << ((ip >> 24) & 0xFF);
  return ss.str();
}

// ============================================================================
// Built-in IP range database
// ============================================================================
// Major IP ranges for well-known providers and country allocations.
// Covers major cloud providers, CDNs, and regional allocations.
// Format: {start_ip_BE, end_ip_BE, country_code, country_name, lat, lng}

const std::vector<GeoIP::IPRange> &GeoIP::getDatabase() {
  static const std::vector<IPRange> db = {
      // === Private / Reserved ===
      {makeIP(10, 0, 0, 0), makeIP(10, 255, 255, 255), "XX", "Private Network",
       0.0, 0.0},
      {makeIP(172, 16, 0, 0), makeIP(172, 31, 255, 255), "XX",
       "Private Network", 0.0, 0.0},
      {makeIP(192, 168, 0, 0), makeIP(192, 168, 255, 255), "XX",
       "Private Network", 0.0, 0.0},
      {makeIP(127, 0, 0, 0), makeIP(127, 255, 255, 255), "XX", "Localhost", 0.0,
       0.0},

      // === United States ===
      // Google
      {makeIP(8, 8, 4, 0), makeIP(8, 8, 8, 255), "US", "United States", 37.751,
       -97.822},
      {makeIP(8, 34, 208, 0), makeIP(8, 35, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(35, 190, 0, 0), makeIP(35, 199, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(142, 250, 0, 0), makeIP(142, 251, 255, 255), "US",
       "United States", 37.751, -97.822},
      {makeIP(172, 217, 0, 0), makeIP(172, 217, 255, 255), "US",
       "United States", 37.751, -97.822},
      {makeIP(216, 58, 192, 0), makeIP(216, 58, 223, 255), "US",
       "United States", 37.751, -97.822},
      // Amazon AWS
      {makeIP(3, 0, 0, 0), makeIP(3, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(52, 0, 0, 0), makeIP(52, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(54, 64, 0, 0), makeIP(54, 95, 255, 255), "JP", "Japan", 36.204,
       138.253},
      {makeIP(54, 144, 0, 0), makeIP(54, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      // Microsoft/Azure
      {makeIP(13, 64, 0, 0), makeIP(13, 107, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(20, 33, 0, 0), makeIP(20, 128, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(40, 74, 0, 0), makeIP(40, 125, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(104, 40, 0, 0), makeIP(104, 47, 255, 255), "US", "United States",
       37.751, -97.822},
      // Cloudflare
      {makeIP(1, 0, 0, 0), makeIP(1, 1, 1, 255), "US", "United States", 37.751,
       -97.822},
      {makeIP(104, 16, 0, 0), makeIP(104, 31, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(172, 64, 0, 0), makeIP(172, 71, 255, 255), "US", "United States",
       37.751, -97.822},
      // Meta/Facebook
      {makeIP(31, 13, 24, 0), makeIP(31, 13, 103, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(157, 240, 0, 0), makeIP(157, 240, 255, 255), "US",
       "United States", 37.751, -97.822},
      // Apple
      {makeIP(17, 0, 0, 0), makeIP(17, 255, 255, 255), "US", "United States",
       37.334, -122.009},
      // Netflix
      {makeIP(23, 246, 0, 0), makeIP(23, 246, 63, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(45, 57, 0, 0), makeIP(45, 57, 127, 255), "US", "United States",
       37.751, -97.822},
      // General US ranges
      {makeIP(4, 0, 0, 0), makeIP(4, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(6, 0, 0, 0), makeIP(7, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(9, 0, 0, 0), makeIP(9, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(11, 0, 0, 0), makeIP(11, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(15, 0, 0, 0), makeIP(15, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(16, 0, 0, 0), makeIP(16, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(18, 0, 0, 0), makeIP(19, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(44, 0, 0, 0), makeIP(44, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(63, 0, 0, 0), makeIP(63, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(64, 0, 0, 0), makeIP(65, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(66, 0, 0, 0), makeIP(66, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(68, 0, 0, 0), makeIP(68, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(69, 0, 0, 0), makeIP(70, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(71, 0, 0, 0), makeIP(76, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(96, 0, 0, 0), makeIP(96, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(98, 0, 0, 0), makeIP(100, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(108, 0, 0, 0), makeIP(108, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(173, 0, 0, 0), makeIP(173, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(174, 0, 0, 0), makeIP(174, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(184, 0, 0, 0), makeIP(184, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(199, 0, 0, 0), makeIP(199, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(204, 0, 0, 0), makeIP(204, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(205, 0, 0, 0), makeIP(205, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(206, 0, 0, 0), makeIP(206, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(207, 0, 0, 0), makeIP(207, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(208, 0, 0, 0), makeIP(208, 255, 255, 255), "US", "United States",
       37.751, -97.822},
      {makeIP(209, 0, 0, 0), makeIP(209, 255, 255, 255), "US", "United States",
       37.751, -97.822},

      // === Europe ===
      // Germany
      {makeIP(5, 0, 0, 0), makeIP(5, 63, 255, 255), "DE", "Germany", 51.165,
       10.452},
      {makeIP(46, 0, 0, 0), makeIP(46, 63, 255, 255), "DE", "Germany", 51.165,
       10.452},
      {makeIP(78, 0, 0, 0), makeIP(78, 63, 255, 255), "DE", "Germany", 51.165,
       10.452},
      {makeIP(80, 0, 0, 0), makeIP(80, 127, 255, 255), "DE", "Germany", 51.165,
       10.452},
      {makeIP(85, 0, 0, 0), makeIP(85, 31, 255, 255), "DE", "Germany", 51.165,
       10.452},
      {makeIP(88, 0, 0, 0), makeIP(88, 79, 255, 255), "DE", "Germany", 51.165,
       10.452},
      {makeIP(91, 0, 0, 0), makeIP(91, 31, 255, 255), "DE", "Germany", 51.165,
       10.452},
      // UK
      {makeIP(2, 16, 0, 0), makeIP(2, 31, 255, 255), "GB", "United Kingdom",
       55.378, -3.436},
      {makeIP(5, 64, 0, 0), makeIP(5, 79, 255, 255), "GB", "United Kingdom",
       55.378, -3.436},
      {makeIP(81, 0, 0, 0), makeIP(81, 191, 255, 255), "GB", "United Kingdom",
       55.378, -3.436},
      {makeIP(86, 0, 0, 0), makeIP(86, 31, 255, 255), "GB", "United Kingdom",
       55.378, -3.436},
      {makeIP(92, 0, 0, 0), makeIP(92, 31, 255, 255), "GB", "United Kingdom",
       55.378, -3.436},
      // France
      {makeIP(2, 0, 0, 0), makeIP(2, 15, 255, 255), "FR", "France", 46.228,
       2.214},
      {makeIP(5, 135, 0, 0), makeIP(5, 135, 255, 255), "FR", "France", 46.228,
       2.214},
      {makeIP(46, 218, 0, 0), makeIP(46, 218, 255, 255), "FR", "France", 46.228,
       2.214},
      {makeIP(62, 0, 0, 0), makeIP(62, 63, 255, 255), "FR", "France", 46.228,
       2.214},
      {makeIP(82, 64, 0, 0), makeIP(82, 127, 255, 255), "FR", "France", 46.228,
       2.214},
      // Netherlands
      {makeIP(31, 186, 0, 0), makeIP(31, 186, 255, 255), "NL", "Netherlands",
       52.133, 5.295},
      {makeIP(37, 48, 0, 0), makeIP(37, 63, 255, 255), "NL", "Netherlands",
       52.133, 5.295},
      {makeIP(77, 166, 0, 0), makeIP(77, 167, 255, 255), "NL", "Netherlands",
       52.133, 5.295},
      // Sweden
      {makeIP(31, 208, 0, 0), makeIP(31, 215, 255, 255), "SE", "Sweden", 60.128,
       18.644},
      {makeIP(46, 246, 0, 0), makeIP(46, 246, 255, 255), "SE", "Sweden", 60.128,
       18.644},
      // Russia
      {makeIP(5, 136, 0, 0), makeIP(5, 143, 255, 255), "RU", "Russia", 61.524,
       105.319},
      {makeIP(31, 128, 0, 0), makeIP(31, 131, 255, 255), "RU", "Russia", 61.524,
       105.319},
      {makeIP(46, 160, 0, 0), makeIP(46, 175, 255, 255), "RU", "Russia", 61.524,
       105.319},
      {makeIP(77, 34, 0, 0), makeIP(77, 35, 255, 255), "RU", "Russia", 61.524,
       105.319},
      {makeIP(77, 37, 0, 0), makeIP(77, 37, 255, 255), "RU", "Russia", 61.524,
       105.319},
      {makeIP(178, 128, 0, 0), makeIP(178, 159, 255, 255), "RU", "Russia",
       61.524, 105.319},
      {makeIP(185, 0, 0, 0), makeIP(185, 31, 255, 255), "RU", "Russia", 61.524,
       105.319},
      // Italy
      {makeIP(2, 32, 0, 0), makeIP(2, 47, 255, 255), "IT", "Italy", 41.872,
       12.567},
      {makeIP(5, 88, 0, 0), makeIP(5, 95, 255, 255), "IT", "Italy", 41.872,
       12.567},
      // Spain
      {makeIP(2, 136, 0, 0), makeIP(2, 143, 255, 255), "ES", "Spain", 40.464,
       -3.749},
      {makeIP(5, 144, 0, 0), makeIP(5, 151, 255, 255), "ES", "Spain", 40.464,
       -3.749},
      // Poland
      {makeIP(5, 172, 0, 0), makeIP(5, 179, 255, 255), "PL", "Poland", 51.920,
       19.145},
      {makeIP(31, 0, 0, 0), makeIP(31, 15, 255, 255), "PL", "Poland", 51.920,
       19.145},

      // === Asia ===
      // China
      {makeIP(1, 24, 0, 0), makeIP(1, 31, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(14, 0, 0, 0), makeIP(14, 31, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(27, 0, 0, 0), makeIP(27, 127, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(36, 0, 0, 0), makeIP(36, 63, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(42, 0, 0, 0), makeIP(42, 127, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(58, 0, 0, 0), makeIP(58, 255, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(59, 0, 0, 0), makeIP(59, 255, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(60, 0, 0, 0), makeIP(61, 255, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(101, 0, 0, 0), makeIP(101, 255, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(106, 0, 0, 0), makeIP(106, 127, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(110, 0, 0, 0), makeIP(111, 255, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(112, 0, 0, 0), makeIP(112, 255, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(113, 0, 0, 0), makeIP(113, 255, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(114, 0, 0, 0), makeIP(114, 255, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(115, 0, 0, 0), makeIP(115, 255, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(116, 0, 0, 0), makeIP(116, 255, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(117, 0, 0, 0), makeIP(117, 255, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(118, 0, 0, 0), makeIP(118, 255, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(119, 0, 0, 0), makeIP(119, 255, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(120, 0, 0, 0), makeIP(120, 255, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(121, 0, 0, 0), makeIP(121, 255, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(122, 0, 0, 0), makeIP(122, 255, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(123, 0, 0, 0), makeIP(123, 255, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(124, 0, 0, 0), makeIP(124, 255, 255, 255), "CN", "China", 35.862,
       104.195},
      {makeIP(125, 0, 0, 0), makeIP(125, 255, 255, 255), "CN", "China", 35.862,
       104.195},
      // Japan
      {makeIP(14, 128, 0, 0), makeIP(14, 191, 255, 255), "JP", "Japan", 36.204,
       138.253},
      {makeIP(27, 80, 0, 0), makeIP(27, 95, 255, 255), "JP", "Japan", 36.204,
       138.253},
      {makeIP(49, 96, 0, 0), makeIP(49, 111, 255, 255), "JP", "Japan", 36.204,
       138.253},
      {makeIP(126, 0, 0, 0), makeIP(126, 255, 255, 255), "JP", "Japan", 36.204,
       138.253},
      {makeIP(133, 0, 0, 0), makeIP(133, 255, 255, 255), "JP", "Japan", 36.204,
       138.253},
      {makeIP(150, 0, 0, 0), makeIP(150, 31, 255, 255), "JP", "Japan", 36.204,
       138.253},
      {makeIP(153, 0, 0, 0), makeIP(153, 255, 255, 255), "JP", "Japan", 36.204,
       138.253},
      {makeIP(163, 0, 0, 0), makeIP(163, 63, 255, 255), "JP", "Japan", 36.204,
       138.253},
      {makeIP(202, 0, 0, 0), makeIP(202, 63, 255, 255), "JP", "Japan", 36.204,
       138.253},
      {makeIP(210, 0, 0, 0), makeIP(210, 255, 255, 255), "JP", "Japan", 36.204,
       138.253},
      // South Korea
      {makeIP(1, 16, 0, 0), makeIP(1, 23, 255, 255), "KR", "South Korea",
       35.907, 127.767},
      {makeIP(14, 32, 0, 0), makeIP(14, 63, 255, 255), "KR", "South Korea",
       35.907, 127.767},
      {makeIP(27, 96, 0, 0), makeIP(27, 127, 255, 255), "KR", "South Korea",
       35.907, 127.767},
      {makeIP(175, 192, 0, 0), makeIP(175, 223, 255, 255), "KR", "South Korea",
       35.907, 127.767},
      {makeIP(211, 0, 0, 0), makeIP(211, 255, 255, 255), "KR", "South Korea",
       35.907, 127.767},
      // India
      {makeIP(1, 32, 0, 0), makeIP(1, 47, 255, 255), "IN", "India", 20.594,
       78.963},
      {makeIP(14, 96, 0, 0), makeIP(14, 127, 255, 255), "IN", "India", 20.594,
       78.963},
      {makeIP(27, 0, 0, 0), makeIP(27, 15, 255, 255), "IN", "India", 20.594,
       78.963},
      {makeIP(49, 32, 0, 0), makeIP(49, 47, 255, 255), "IN", "India", 20.594,
       78.963},
      {makeIP(103, 0, 0, 0), makeIP(103, 63, 255, 255), "IN", "India", 20.594,
       78.963},
      {makeIP(106, 192, 0, 0), makeIP(106, 223, 255, 255), "IN", "India",
       20.594, 78.963},
      {makeIP(122, 160, 0, 0), makeIP(122, 191, 255, 255), "IN", "India",
       20.594, 78.963},
      {makeIP(182, 64, 0, 0), makeIP(182, 79, 255, 255), "IN", "India", 20.594,
       78.963},
      // Singapore
      {makeIP(27, 124, 0, 0), makeIP(27, 125, 255, 255), "SG", "Singapore",
       1.352, 103.820},
      {makeIP(54, 254, 0, 0), makeIP(54, 255, 255, 255), "SG", "Singapore",
       1.352, 103.820},
      {makeIP(175, 41, 128, 0), makeIP(175, 41, 255, 255), "SG", "Singapore",
       1.352, 103.820},

      // === Oceania ===
      // Australia
      {makeIP(1, 120, 0, 0), makeIP(1, 127, 255, 255), "AU", "Australia",
       -25.274, 133.775},
      {makeIP(14, 192, 0, 0), makeIP(14, 207, 255, 255), "AU", "Australia",
       -25.274, 133.775},
      {makeIP(49, 176, 0, 0), makeIP(49, 191, 255, 255), "AU", "Australia",
       -25.274, 133.775},
      {makeIP(103, 192, 0, 0), makeIP(103, 255, 255, 255), "AU", "Australia",
       -25.274, 133.775},
      {makeIP(203, 0, 0, 0), makeIP(203, 63, 255, 255), "AU", "Australia",
       -25.274, 133.775},

      // === South America ===
      // Brazil
      {makeIP(131, 72, 0, 0), makeIP(131, 72, 255, 255), "BR", "Brazil",
       -14.235, -51.925},
      {makeIP(143, 0, 0, 0), makeIP(143, 63, 255, 255), "BR", "Brazil", -14.235,
       -51.925},
      {makeIP(152, 240, 0, 0), makeIP(152, 255, 255, 255), "BR", "Brazil",
       -14.235, -51.925},
      {makeIP(164, 0, 0, 0), makeIP(164, 31, 255, 255), "BR", "Brazil", -14.235,
       -51.925},
      {makeIP(177, 0, 0, 0), makeIP(177, 255, 255, 255), "BR", "Brazil",
       -14.235, -51.925},
      {makeIP(179, 0, 0, 0), makeIP(179, 255, 255, 255), "BR", "Brazil",
       -14.235, -51.925},
      {makeIP(186, 0, 0, 0), makeIP(186, 255, 255, 255), "BR", "Brazil",
       -14.235, -51.925},
      {makeIP(187, 0, 0, 0), makeIP(187, 255, 255, 255), "BR", "Brazil",
       -14.235, -51.925},
      {makeIP(189, 0, 0, 0), makeIP(189, 255, 255, 255), "BR", "Brazil",
       -14.235, -51.925},
      {makeIP(200, 0, 0, 0), makeIP(200, 255, 255, 255), "BR", "Brazil",
       -14.235, -51.925},
      {makeIP(201, 0, 0, 0), makeIP(201, 127, 255, 255), "BR", "Brazil",
       -14.235, -51.925},

      // === Africa ===
      // South Africa
      {makeIP(41, 0, 0, 0), makeIP(41, 63, 255, 255), "ZA", "South Africa",
       -30.559, 22.937},
      {makeIP(102, 0, 0, 0), makeIP(102, 31, 255, 255), "ZA", "South Africa",
       -30.559, 22.937},
      {makeIP(154, 0, 0, 0), makeIP(154, 127, 255, 255), "ZA", "South Africa",
       -30.559, 22.937},
      {makeIP(196, 0, 0, 0), makeIP(196, 255, 255, 255), "ZA", "South Africa",
       -30.559, 22.937},
      {makeIP(197, 0, 0, 0), makeIP(197, 255, 255, 255), "ZA", "South Africa",
       -30.559, 22.937},

      // === Canada ===
      {makeIP(24, 0, 0, 0), makeIP(24, 63, 255, 255), "CA", "Canada", 56.130,
       -106.347},
      {makeIP(47, 128, 0, 0), makeIP(47, 191, 255, 255), "CA", "Canada", 56.130,
       -106.347},
      {makeIP(99, 224, 0, 0), makeIP(99, 255, 255, 255), "CA", "Canada", 56.130,
       -106.347},
      {makeIP(142, 0, 0, 0), makeIP(142, 31, 255, 255), "CA", "Canada", 56.130,
       -106.347},
  };
  return db;
}

// ============================================================================
// IP Lookup
// ============================================================================
GeoLocation GeoIP::lookup(uint32_t ip_le) {
  uint32_t ip_be = ipToNetworkOrder(ip_le);

  const auto &db = getDatabase();
  for (const auto &range : db) {
    if (ip_be >= range.start && ip_be <= range.end) {
      return {range.country_code, range.country_name, range.lat, range.lng};
    }
  }

  // Unknown — return generic
  return {"--", "Unknown", 0.0, 0.0};
}

GeoLocation GeoIP::lookup(const std::string &ip_str) {
  // Parse "A.B.C.D" to uint32_t (little-endian, like our packet parser stores
  // it)
  uint32_t result = 0;
  int octet = 0, shift = 0;
  for (char c : ip_str) {
    if (c == '.') {
      result |= (octet << shift);
      shift += 8;
      octet = 0;
    } else if (c >= '0' && c <= '9') {
      octet = octet * 10 + (c - '0');
    }
  }
  result |= (octet << shift);
  return lookup(result);
}

} // namespace DPI
