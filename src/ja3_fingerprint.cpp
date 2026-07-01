#include "ja3_fingerprint.h"
#include "sni_extractor.h"
#include <cstring>
#include <iomanip>
#include <sstream>
#include <unordered_map>

namespace DPI {

// ============================================================================
// GREASE values (RFC 8701)
// Pattern: 0x?a?a where ? is the same nibble
// ============================================================================
bool JA3Fingerprint::isGREASE(uint16_t value) {
  // GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa
  if ((value & 0x0f0f) != 0x0a0a)
    return false;
  return ((value >> 8) & 0xf0) == ((value & 0xf0) << 4 >> 4 << 4 >> 4 << 4)
             ? ((value >> 8) == (value & 0xff))
             : false;
}

uint16_t JA3Fingerprint::readUint16BE(const uint8_t *data) {
  return (static_cast<uint16_t>(data[0]) << 8) | data[1];
}

uint32_t JA3Fingerprint::readUint24BE(const uint8_t *data) {
  return (static_cast<uint32_t>(data[0]) << 16) |
         (static_cast<uint32_t>(data[1]) << 8) | data[2];
}

std::string JA3Fingerprint::joinValues(const std::vector<uint16_t> &values) {
  std::string result;
  for (size_t i = 0; i < values.size(); i++) {
    if (i > 0)
      result += '-';
    result += std::to_string(values[i]);
  }
  return result;
}

// ============================================================================
// MD5 Implementation (RFC 1321)
// Self-contained — no OpenSSL or external library needed
// ============================================================================
static inline uint32_t md5_F(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) | (~x & z);
}
static inline uint32_t md5_G(uint32_t x, uint32_t y, uint32_t z) {
  return (x & z) | (y & ~z);
}
static inline uint32_t md5_H(uint32_t x, uint32_t y, uint32_t z) {
  return x ^ y ^ z;
}
static inline uint32_t md5_I(uint32_t x, uint32_t y, uint32_t z) {
  return y ^ (x | ~z);
}
static inline uint32_t md5_rotate_left(uint32_t x, int n) {
  return (x << n) | (x >> (32 - n));
}

std::string JA3Fingerprint::md5(const std::string &input) {
  // Per-round shift amounts
  static const int s[64] = {7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 7,
                            12, 17, 22, 5,  9,  14, 20, 5,  9,  14, 20, 5,  9,
                            14, 20, 5,  9,  14, 20, 4,  11, 16, 23, 4,  11, 16,
                            23, 4,  11, 16, 23, 4,  11, 16, 23, 6,  10, 15, 21,
                            6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21};

  // Precomputed constants (floor(2^32 * abs(sin(i+1))))
  static const uint32_t K[64] = {
      0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
      0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
      0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
      0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
      0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
      0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
      0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
      0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
      0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
      0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
      0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

  // Initialize hash values
  uint32_t a0 = 0x67452301;
  uint32_t b0 = 0xefcdab89;
  uint32_t c0 = 0x98badcfe;
  uint32_t d0 = 0x10325476;

  // Pre-processing: adding padding bits
  std::vector<uint8_t> msg(input.begin(), input.end());
  uint64_t original_bit_len = msg.size() * 8;

  msg.push_back(0x80);
  while (msg.size() % 64 != 56) {
    msg.push_back(0x00);
  }

  // Append original length in bits as 64-bit little-endian
  for (int i = 0; i < 8; i++) {
    msg.push_back(static_cast<uint8_t>((original_bit_len >> (i * 8)) & 0xFF));
  }

  // Process each 512-bit (64-byte) block
  for (size_t offset = 0; offset < msg.size(); offset += 64) {
    uint32_t M[16];
    for (int i = 0; i < 16; i++) {
      M[i] = static_cast<uint32_t>(msg[offset + i * 4]) |
             (static_cast<uint32_t>(msg[offset + i * 4 + 1]) << 8) |
             (static_cast<uint32_t>(msg[offset + i * 4 + 2]) << 16) |
             (static_cast<uint32_t>(msg[offset + i * 4 + 3]) << 24);
    }

    uint32_t A = a0, B = b0, C = c0, D = d0;

    for (int i = 0; i < 64; i++) {
      uint32_t F_val, g;
      if (i < 16) {
        F_val = md5_F(B, C, D);
        g = i;
      } else if (i < 32) {
        F_val = md5_G(B, C, D);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        F_val = md5_H(B, C, D);
        g = (3 * i + 5) % 16;
      } else {
        F_val = md5_I(B, C, D);
        g = (7 * i) % 16;
      }

      F_val = F_val + A + K[i] + M[g];
      A = D;
      D = C;
      C = B;
      B = B + md5_rotate_left(F_val, s[i]);
    }

    a0 += A;
    b0 += B;
    c0 += C;
    d0 += D;
  }

  // Produce the final hash as hex string (little-endian)
  std::ostringstream result;
  auto appendLE = [&result](uint32_t val) {
    for (int i = 0; i < 4; i++) {
      result << std::hex << std::setfill('0') << std::setw(2)
             << ((val >> (i * 8)) & 0xFF);
    }
  };
  appendLE(a0);
  appendLE(b0);
  appendLE(c0);
  appendLE(d0);

  return result.str();
}

// ============================================================================
// JA3 Fingerprint Extraction
// ============================================================================
std::optional<JA3Result> JA3Fingerprint::fingerprint(const uint8_t *payload,
                                                     size_t length) {
  // Verify TLS Client Hello
  if (!SNIExtractor::isTLSClientHello(payload, length)) {
    return std::nullopt;
  }

  // Skip TLS record header (5 bytes)
  size_t offset = 5;

  // Skip handshake type (1) + length (3) = 4 bytes
  offset += 4;

  // ---- Client Hello Body ----

  // TLS version from Client Hello body (bytes 0-1)
  if (offset + 2 > length)
    return std::nullopt;
  uint16_t tls_version = readUint16BE(payload + offset);
  offset += 2;

  // Skip Random (32 bytes)
  offset += 32;

  // Skip Session ID
  if (offset >= length)
    return std::nullopt;
  uint8_t session_id_len = payload[offset];
  offset += 1 + session_id_len;

  // ---- Cipher Suites ----
  if (offset + 2 > length)
    return std::nullopt;
  uint16_t cipher_suites_len = readUint16BE(payload + offset);
  offset += 2;

  std::vector<uint16_t> cipher_suites;
  size_t cs_end = offset + cipher_suites_len;
  if (cs_end > length)
    return std::nullopt;

  while (offset + 2 <= cs_end) {
    uint16_t cs = readUint16BE(payload + offset);
    offset += 2;
    if (!isGREASE(cs)) {
      cipher_suites.push_back(cs);
    }
  }
  offset = cs_end;

  // Skip Compression Methods
  if (offset >= length)
    return std::nullopt;
  uint8_t comp_len = payload[offset];
  offset += 1 + comp_len;

  // ---- Extensions ----
  std::vector<uint16_t> extensions;
  std::vector<uint16_t> elliptic_curves;
  std::vector<uint16_t> ec_point_formats;

  if (offset + 2 <= length) {
    uint16_t extensions_len = readUint16BE(payload + offset);
    offset += 2;

    size_t ext_end = offset + extensions_len;
    if (ext_end > length)
      ext_end = length;

    while (offset + 4 <= ext_end) {
      uint16_t ext_type = readUint16BE(payload + offset);
      uint16_t ext_data_len = readUint16BE(payload + offset + 2);
      offset += 4;

      if (offset + ext_data_len > ext_end)
        break;

      if (!isGREASE(ext_type)) {
        extensions.push_back(ext_type);
      }

      // Extract supported_groups (elliptic curves) — extension type 0x000a
      if (ext_type == 0x000a && ext_data_len >= 2) {
        uint16_t list_len = readUint16BE(payload + offset);
        size_t curve_offset = offset + 2;
        size_t curve_end = offset + 2 + list_len;
        if (curve_end > offset + ext_data_len)
          curve_end = offset + ext_data_len;

        while (curve_offset + 2 <= curve_end) {
          uint16_t curve = readUint16BE(payload + curve_offset);
          curve_offset += 2;
          if (!isGREASE(curve)) {
            elliptic_curves.push_back(curve);
          }
        }
      }

      // Extract ec_point_formats — extension type 0x000b
      if (ext_type == 0x000b && ext_data_len >= 1) {
        uint8_t fmt_len = payload[offset];
        for (uint8_t i = 0;
             i < fmt_len && (offset + 1 + i) < offset + ext_data_len; i++) {
          ec_point_formats.push_back(payload[offset + 1 + i]);
        }
      }

      offset += ext_data_len;
    }
  }

  // Build JA3 string:
  // TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats
  std::string ja3_string =
      std::to_string(tls_version) + "," + joinValues(cipher_suites) + "," +
      joinValues(extensions) + "," + joinValues(elliptic_curves) + "," +
      joinValues(ec_point_formats);

  JA3Result result;
  result.ja3_string = ja3_string;
  result.ja3_hash = md5(ja3_string);

  return result;
}

// ============================================================================
// Known JA3 Hash Lookup Table
// ============================================================================
std::string JA3Fingerprint::lookupJA3(const std::string &hash) {
  // Well-known JA3 hashes for common applications
  // Source: ja3er.com and various threat intelligence databases
  static const std::unordered_map<std::string, std::string> known_hashes = {
      // Browsers
      {"cd08e31494f9531f560d64c695473da9", "Chrome (Windows)"},
      {"b32309a26951912be7dba376398abc3b", "Chrome (macOS)"},
      {"bc6c386f480ee97b9d9e52d472b772d8", "Chrome (Linux)"},
      {"a0e9f5d64349fb13191bc781f81f42e1", "Firefox (Windows)"},
      {"e4f26f62c99532b07e15f83e8e750a75", "Firefox (macOS)"},
      {"839bbe3ed0514d63e64af4b5ce37c69a", "Firefox (Linux)"},
      {"109f6f3e43202e3731044bf71953c9e0", "Safari (macOS)"},
      {"773906b0efdefa24a7f2b8eb6985bf37", "Safari (iOS)"},
      {"2b91012da4ac9a3e3002d7ae5e1f2979", "Edge (Windows)"},

      // CLI/Tools
      {"3b5074b1b5d032e5620f69f9f700ff0e", "curl"},
      {"36f7277af969a6947a61ae0b815907a1", "wget"},
      {"d2e6c30bed2953195c94a5d0bdc9cb52", "Python requests"},
      {"6734f37431670b3ab4292b8f60f29984", "Go net/http"},

      // Bots/Malware indicators
      {"e7d705a3286e19ea42f587b344ee6865", "Tofsee Malware"},
      {"4d7a28d6f2263ed61de88ca66eb011e3", "Emotet Malware"},
      {"51c64c77e60f3980eea90869b68c58a8", "Trickbot"},

      // Other
      {"b386946a5a44d1ddcc843bc75336dfce", "Node.js HTTPS"},
      {"7c02dbae662670040c7af9bd15fb7e2f", "Java (OpenJDK)"},
      {"2d1eb5817ece335c24904f5162526949", "Tor Browser"},
  };

  auto it = known_hashes.find(hash);
  if (it != known_hashes.end()) {
    return it->second;
  }
  return "";
}

} // namespace DPI
