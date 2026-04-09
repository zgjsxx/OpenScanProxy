#include "openscanproxy/admin/admin_server.hpp"

#include "openscanproxy/core/util.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <sstream>
#include <thread>

namespace openscanproxy::admin {
namespace {
std::string http_resp(int status, const std::string& reason, const std::string& body, const std::string& ct = "text/html",
                      const std::string& extra_headers = "") {
  std::ostringstream os;
  os << "HTTP/1.1 " << status << ' ' << reason << "\r\n"
     << "Content-Type: " << ct << "\r\n"
     << "Content-Length: " << body.size() << "\r\n"
     << extra_headers << "Connection: close\r\n\r\n"
     << body;
  return os.str();
}

bool logged_in(const std::string& req) { return req.find("Cookie: session=ok") != std::string::npos; }
}  // namespace

void AdminServer::run() {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(runtime_.config.admin_listen_port);
  inet_pton(AF_INET, runtime_.config.admin_listen_host.c_str(), &addr.sin_addr);
  bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  listen(fd, 64);

  while (true) {
    int c = accept(fd, nullptr, nullptr);
    if (c < 0) continue;
    std::thread([this, c]() {
      char buf[8192] = {0};
      auto n = recv(c, buf, sizeof(buf) - 1, 0);
      if (n <= 0) {
        close(c);
        return;
      }
      std::string req(buf, n);
      auto line_end = req.find("\r\n");
      auto first = req.substr(0, line_end);
      std::istringstream fl(first);
      std::string method, path;
      fl >> method >> path;

      std::string resp;
      if (path == "/healthz" || path == "/readyz") {
        resp = http_resp(200, "OK", "ok", "text/plain");
      } else if (path == "/metrics") {
        resp = http_resp(200, "OK", runtime_.stats.to_metrics_text(), "text/plain");
      } else if (path == "/login" && method == "GET") {
        std::string body = "<html><body><h2>OpenScanProxy Login</h2><form method='POST' action='/login'>"
                           "<input name='u' placeholder='username'/><input type='password' name='p' placeholder='password'/>"
                           "<button type='submit'>Login</button></form></body></html>";
        resp = http_resp(200, "OK", body);
      } else if (path == "/login" && method == "POST") {
        bool ok = req.find("u=" + runtime_.config.admin_user) != std::string::npos &&
                  req.find("p=" + runtime_.config.admin_password) != std::string::npos;
        if (ok) {
          resp = http_resp(302, "Found", "", "text/plain", "Set-Cookie: session=ok; HttpOnly\r\nLocation: /\r\n");
        } else {
          resp = http_resp(401, "Unauthorized", "bad credentials", "text/plain");
        }
      } else if (!logged_in(req)) {
        resp = http_resp(302, "Found", "", "text/plain", "Location: /login\r\n");
      } else if (path == "/") {
        auto s = runtime_.stats.snapshot();
        std::ostringstream body;
        body << "<html><body><h1>OpenScanProxy Dashboard</h1><ul>"
             << "<li>total_requests: " << s.total_requests << "</li>"
             << "<li>https_mitm_requests: " << s.https_mitm_requests << "</li>"
             << "<li>scanned_files: " << s.scanned_files << "</li>"
             << "<li>clean: " << s.clean << "</li>"
             << "<li>infected: " << s.infected << "</li>"
             << "<li>blocked: " << s.blocked << "</li>"
             << "<li>scanner_error: " << s.scanner_error << "</li></ul>"
             << "<a href='/logs'>logs</a> | <a href='/config'>config</a></body></html>";
        resp = http_resp(200, "OK", body.str());
      } else if (path == "/logs") {
        auto logs = runtime_.audit.latest(100);
        std::ostringstream body;
        body << "<html><body><h2>Audit Logs</h2><table border='1'><tr><th>time</th><th>url</th><th>file</th><th>sha256</th><th>result</th><th>action</th><th>sig</th></tr>";
        for (const auto& e : logs) {
          body << "<tr><td>" << e.timestamp << "</td><td>" << e.url << "</td><td>" << e.filename << "</td><td>" << e.sha256
               << "</td><td>" << e.result << "</td><td>" << e.action << "</td><td>" << e.signature << "</td></tr>";
        }
        body << "</table></body></html>";
        resp = http_resp(200, "OK", body.str());
      } else if (path == "/config") {
        const auto& c = runtime_.config;
        std::ostringstream body;
        body << "<html><body><h2>Config</h2><pre>"
             << "proxy=" << c.proxy_listen_host << ":" << c.proxy_listen_port << "\n"
             << "https_mitm=" << (c.enable_https_mitm ? "true" : "false") << "\n"
             << "scanner=" << c.scanner_type << "\n"
             << "max_scan_file_size=" << c.max_scan_file_size << "\n"
             << "policy_mode=" << c.policy_mode << "\n"
             << "scan_upload=" << c.scan_upload << " scan_download=" << c.scan_download << "\n"
             << "</pre></body></html>";
        resp = http_resp(200, "OK", body.str());
      } else {
        resp = http_resp(404, "Not Found", "not found", "text/plain");
      }
      send(c, resp.data(), resp.size(), 0);
      close(c);
    }).detach();
  }
}

}  // namespace openscanproxy::admin
