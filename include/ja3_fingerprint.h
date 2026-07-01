#ifndef JA3_FINGERPRINT_H
#define JA3_FINGERPRINT_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace DPI {

// ============================================================================
// JA3 Fingerprint - TLS Client Fingerprinting
// ============================================================================
//
// JA3 creates a fingerprint of a TLS client by hashing specific fields
// from the Client Hello message. The same application (Chrome, Firefox,
// curl, etc.) will always produce the same JA3 hash regardless of
// the server it connects to.
//
// JA3 String Format:
//   TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats
//
// Example:
//   769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
//
// JA3 Hash:
//   MD5(JA3 String) = "ada70206e40642a3e4461f35503241d5"
//
// GREASE values (0x?a?a pattern) are always excluded from the hash
// to ensure cross-implementation consistency.
//
// Reference: https://github.com/salesforce/ja3
// ============================================================================

struct JA3Result {
  std::string ja3_string; // Raw JA3 string (human-readable)
  std::string ja3_hash;   // MD5 hash of ja3_string
};

class JA3Fingerprint {
public:
  // Extract JA3 fingerprint from a TLS Client Hello payload
  // payload should point to the start of TCP payload (TLS record)
  static std::optional<JA3Result> fingerprint(const uint8_t *payload,
                                              size_t length);

  // Look up a known JA3 hash and return the application name
  // Returns empty string if unknown
  static std::string lookupJA3(const std::string &hash);

private:
  // GREASE values defined by RFC 8701 — must be excluded from JA3
  static bool isGREASE(uint16_t value);

  // Helper to read big-endian values
  static uint16_t readUint16BE(const uint8_t *data);
  static uint32_t readUint24BE(const uint8_t *data);

  // Lightweight MD5 implementation (no external dependency)
  static std::string md5(const std::string &input);

  // Join a vector of uint16_t as dash-separated string
  static std::string joinValues(const std::vector<uint16_t> &values);
};

} // namespace DPI

#endif // JA3_FINGERPRINT_H
