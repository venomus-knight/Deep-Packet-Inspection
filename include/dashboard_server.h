#ifndef DASHBOARD_SERVER_H
#define DASHBOARD_SERVER_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

namespace DPI {

// Callback that returns JSON stats string on demand
using StatsProvider = std::function<std::string()>;

// ============================================================================
// DashboardServer - Minimal embedded HTTP server for the DPI dashboard
// ============================================================================
class DashboardServer {
public:
  explicit DashboardServer(int port = 8080);
  ~DashboardServer();

  // Set the function that provides JSON stats
  void setStatsProvider(StatsProvider provider);

  // Start serving (non-blocking, runs in a background thread)
  bool start();

  // Stop the server
  void stop();

  // Get the port
  int port() const { return port_; }

private:
  int port_;
  int server_fd_ = -1;
  std::atomic<bool> running_{false};
  std::thread server_thread_;
  StatsProvider stats_provider_;

  void serverLoop();
  void handleClient(int client_fd);

  // HTTP response helpers
  static void sendResponse(int client_fd, int status_code,
                           const std::string &content_type,
                           const std::string &body);
  static std::string getStatusText(int status_code);

  // The embedded HTML dashboard (returned for GET /)
  static std::string getDashboardHTML();
};

} // namespace DPI

#endif // DASHBOARD_SERVER_H
