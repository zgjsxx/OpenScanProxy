#include "openscanproxy/admin/admin_server.hpp"

#include "openscanproxy/core/util.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <map>
#include <sstream>
#include <thread>

namespace openscanproxy::admin {
namespace {
std::string http_resp(int status, const std::string& reason, const std::string& body,
                      const std::string& ct = "text/html; charset=utf-8", const std::string& extra_headers = "") {
  std::ostringstream os;
  os << "HTTP/1.1 " << status << ' ' << reason << "\r\n"
     << "Content-Type: " << ct << "\r\n"
     << "Cache-Control: no-store\r\n"
     << "Content-Length: " << body.size() << "\r\n"
     << extra_headers << "Connection: close\r\n\r\n"
     << body;
  return os.str();
}

bool logged_in(const std::string& req) { return req.find("Cookie: session=ok") != std::string::npos; }

std::string get_body(const std::string& req) {
  auto pos = req.find("\r\n\r\n");
  if (pos == std::string::npos) return "";
  return req.substr(pos + 4);
}

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

std::map<std::string, std::string> parse_form(const std::string& body) {
  std::map<std::string, std::string> out;
  auto pairs = core::split(body, '&');
  for (const auto& p : pairs) {
    auto eq = p.find('=');
    if (eq == std::string::npos) continue;
    out[p.substr(0, eq)] = p.substr(eq + 1);
  }
  return out;
}

std::string esc(const std::string& text) {
  std::string out;
  out.reserve(text.size());
  for (char c : text) {
    switch (c) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '\"': out += "&quot;"; break;
      case '\'': out += "&#39;"; break;
      default: out.push_back(c); break;
    }
  }
  return out;
}

std::string admin_shell_html() {
  return R"HTML(
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>OpenScanProxy Enterprise Console</title>
<style>
  :root { --bg:#0b1220; --panel:#111a2f; --card:#1a2741; --txt:#e7eefc; --muted:#9fb3d1; --ok:#38d39f; --warn:#ffce6a; --bad:#ff7d7d; --acc:#74a7ff; }
  body { margin:0; font-family: Inter, system-ui, sans-serif; background:var(--bg); color:var(--txt); }
  .wrap { max-width:1200px; margin:0 auto; padding:20px; }
  h1 { margin:0 0 8px; }
  .sub { color:var(--muted); margin-bottom:20px; }
  .grid { display:grid; grid-template-columns: repeat(auto-fit,minmax(180px,1fr)); gap:12px; }
  .card { background:var(--panel); border:1px solid #243458; border-radius:10px; padding:12px; }
  .k { color:var(--muted); font-size:13px; }
  .v { font-size:26px; margin-top:4px; }
  .tabs { display:flex; gap:8px; margin:16px 0; flex-wrap: wrap; }
  button, input, select { background:#1f2d4d; color:var(--txt); border:1px solid #355084; border-radius:8px; padding:8px 10px; }
  button.active { background:var(--acc); color:#0b1220; font-weight:700; }
  .panel { display:none; background:var(--panel); border:1px solid #243458; border-radius:10px; padding:14px; }
  .panel.active { display:block; }
  table { width:100%; border-collapse: collapse; font-size:13px; }
  th, td { border-bottom:1px solid #243458; text-align:left; padding:8px 4px; vertical-align:top; }
  .row { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:10px; }
  .pill { display:inline-block; padding:2px 8px; border-radius:99px; font-size:12px; }
  .allow{ background:rgba(56,211,159,.15); color:var(--ok);} .block{ background:rgba(255,125,125,.15); color:var(--bad);} .log{ background:rgba(255,206,106,.15); color:var(--warn);} 
  .muted { color:var(--muted); }
</style>
</head>
<body>
  <div class="wrap">
    <h1>OpenScanProxy 企业控制台</h1>
    <div class="sub">实时流量可视化 / 访问日志审计 / Policy配置 / 检索查询</div>

    <div class="grid" id="kpi"></div>

    <div class="tabs">
      <button class="active" data-tab="logs">访问日志</button>
      <button data-tab="policy">Policy 设置</button>
      <button data-tab="traffic">流量趋势</button>
      <button data-tab="system">系统信息</button>
      <a href="/metrics" target="_blank"><button>原始 Metrics</button></a>
      <a href="/logout"><button>退出</button></a>
    </div>

    <div class="panel active" id="logs">
      <div class="row">
        <input id="q" placeholder="搜索 URL/host/文件名/签名" style="min-width:280px" />
        <select id="action"><option value="">全部动作</option><option>allow</option><option>block</option><option>log</option></select>
        <select id="result"><option value="">全部结果</option><option>clean</option><option>infected</option><option>suspicious</option><option>error</option></select>
        <input id="host" placeholder="host过滤" />
        <button onclick="loadLogs()">查询</button>
      </div>
      <div class="muted" id="logHint"></div>
      <table>
        <thead><tr><th>时间</th><th>客户端</th><th>主机</th><th>URL</th><th>文件</th><th>结果</th><th>动作</th><th>签名</th></tr></thead>
        <tbody id="logBody"></tbody>
      </table>
    </div>

    <div class="panel" id="policy">
      <div class="row">
        <label><input type="checkbox" id="failOpen" /> 扫描错误时放行（fail-open）</label>
        <label><input type="checkbox" id="blockSuspicious" /> 拦截 suspicious</label>
      </div>
      <div class="row">
        <button onclick="savePolicy()">保存 Policy</button>
        <span id="policyMsg" class="muted"></span>
      </div>
    </div>

    <div class="panel" id="traffic">
      <canvas id="trafficCanvas" width="1100" height="220" style="width:100%;background:#0d1730;border-radius:8px"></canvas>
      <div class="muted">基于最近请求日志的分钟粒度趋势。</div>
    </div>

    <div class="panel" id="system"><pre id="systemPre"></pre></div>
  </div>

<script>
const kpiKeys = ['total_requests','https_mitm_requests','scanned_files','clean','infected','suspicious','blocked','scanner_error'];

for (const b of document.querySelectorAll('[data-tab]')) {
  b.onclick = () => {
    document.querySelectorAll('[data-tab]').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.getElementById(b.dataset.tab).classList.add('active');
  };
}

async function loadStats() {
  const r = await fetch('/api/stats');
  const s = await r.json();
  const kpi = document.getElementById('kpi');
  kpi.innerHTML = '';
  for (const key of kpiKeys) {
    const div = document.createElement('div');
    div.className = 'card';
    div.innerHTML = `<div class="k">${key}</div><div class="v">${s[key] ?? 0}</div>`;
    kpi.appendChild(div);
  }
}

async function loadLogs() {
  const p = new URLSearchParams();
  for (const id of ['q','action','result','host']) {
    const v = document.getElementById(id).value.trim();
    if (v) p.set(id, v);
  }
  p.set('limit', '300');
  const r = await fetch('/api/logs?' + p.toString());
  const logs = await r.json();
  document.getElementById('logHint').textContent = `命中 ${logs.length} 条`;
  const tb = document.getElementById('logBody');
  tb.innerHTML = '';
  for (const e of logs) {
    const tr = document.createElement('tr');
    const pill = `<span class="pill ${e.action}">${e.action}</span>`;
    tr.innerHTML = `<td>${e.timestamp}</td><td>${e.client_addr||''}</td><td>${e.host||''}</td><td>${e.url||''}</td><td>${e.filename||''}</td><td>${e.result||''}</td><td>${pill}</td><td>${e.signature||''}</td>`;
    tb.appendChild(tr);
  }
  drawTraffic(logs);
}

function drawTraffic(logs) {
  const c = document.getElementById('trafficCanvas');
  const ctx = c.getContext('2d');
  ctx.clearRect(0,0,c.width,c.height);
  const buckets = new Map();
  for (const e of logs) {
    const k = (e.timestamp || '').slice(0,16);
    if (!k) continue;
    buckets.set(k, (buckets.get(k)||0)+1);
  }
  const keys = [...buckets.keys()].sort();
  if (!keys.length) return;
  const vals = keys.map(k => buckets.get(k));
  const max = Math.max(...vals, 1);
  ctx.strokeStyle = '#74a7ff';
  ctx.lineWidth = 2;
  ctx.beginPath();
  keys.forEach((k,i) => {
    const x = 20 + (i * (c.width-40) / Math.max(keys.length-1,1));
    const y = c.height - 20 - (vals[i] * (c.height-40) / max);
    i ? ctx.lineTo(x,y) : ctx.moveTo(x,y);
  });
  ctx.stroke();
}

async function loadPolicy() {
  const r = await fetch('/api/policy');
  const p = await r.json();
  document.getElementById('failOpen').checked = !!p.fail_open;
  document.getElementById('blockSuspicious').checked = !!p.block_suspicious;
}

async function savePolicy() {
  const payload = {
    fail_open: document.getElementById('failOpen').checked,
    block_suspicious: document.getElementById('blockSuspicious').checked
  };
  const r = await fetch('/api/policy', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
  document.getElementById('policyMsg').textContent = r.ok ? '保存成功' : '保存失败';
  await loadSystem();
}

async function loadSystem() {
  const r = await fetch('/api/config');
  const c = await r.json();
  document.getElementById('systemPre').textContent = JSON.stringify(c, null, 2);
}

setInterval(loadStats, 3000);
setInterval(loadLogs, 5000);
loadStats(); loadLogs(); loadPolicy(); loadSystem();
</script>
</body></html>)HTML";
}

std::string stats_to_json(const stats::Snapshot& s) {
  std::ostringstream os;
  os << "{";
  os << "\"total_requests\":" << s.total_requests << ",";
  os << "\"https_mitm_requests\":" << s.https_mitm_requests << ",";
  os << "\"scanned_files\":" << s.scanned_files << ",";
  os << "\"clean\":" << s.clean << ",";
  os << "\"infected\":" << s.infected << ",";
  os << "\"suspicious\":" << s.suspicious << ",";
  os << "\"blocked\":" << s.blocked << ",";
  os << "\"scanner_error\":" << s.scanner_error;
  os << "}";
  return os.str();
}

std::string config_to_json(const proxy::Runtime& runtime) {
  auto p = runtime.policy.config();
  const auto& c = runtime.config;
  std::ostringstream os;
  os << "{";
  os << "\"proxy\":\"" << core::json_escape(c.proxy_listen_host + ":" + std::to_string(c.proxy_listen_port)) << "\",";
  os << "\"admin\":\"" << core::json_escape(c.admin_listen_host + ":" + std::to_string(c.admin_listen_port)) << "\",";
  os << "\"https_mitm\":" << (c.enable_https_mitm ? "true" : "false") << ",";
  os << "\"scanner\":\"" << core::json_escape(c.scanner_type) << "\",";
  os << "\"policy_mode\":\"" << (p.fail_open ? "fail-open" : "fail-close") << "\",";
  os << "\"suspicious_action\":\"" << (p.block_suspicious ? "block" : "log") << "\"";
  os << "}";
  return os.str();
}

std::map<std::string, std::string> parse_query(const std::string& path) {
  std::map<std::string, std::string> out;
  auto q = path.find('?');
  if (q == std::string::npos) return out;
  for (const auto& seg : core::split(path.substr(q + 1), '&')) {
    auto eq = seg.find('=');
    if (eq == std::string::npos) continue;
    out[seg.substr(0, eq)] = seg.substr(eq + 1);
  }
  return out;
}

std::string logs_to_json(const std::vector<audit::AuditEvent>& logs) {
  std::ostringstream os;
  os << "[";
  for (size_t i = 0; i < logs.size(); ++i) {
    const auto& e = logs[i];
    if (i) os << ',';
    os << "{";
    os << "\"timestamp\":\"" << core::json_escape(e.timestamp) << "\",";
    os << "\"client_addr\":\"" << core::json_escape(e.client_addr) << "\",";
    os << "\"host\":\"" << core::json_escape(e.host) << "\",";
    os << "\"url\":\"" << core::json_escape(e.url) << "\",";
    os << "\"method\":\"" << core::json_escape(e.method) << "\",";
    os << "\"filename\":\"" << core::json_escape(e.filename) << "\",";
    os << "\"result\":\"" << core::json_escape(e.result) << "\",";
    os << "\"action\":\"" << core::json_escape(e.action) << "\",";
    os << "\"signature\":\"" << core::json_escape(e.signature) << "\"";
    os << "}";
  }
  os << "]";
  return os.str();
}

std::vector<audit::AuditEvent> filter_logs(std::vector<audit::AuditEvent> logs, const std::map<std::string, std::string>& q) {
  int limit = 100;
  if (auto it = q.find("limit"); it != q.end()) {
    limit = std::max(1, std::min(1000, std::stoi(it->second)));
  }
  const auto word = lower(q.count("q") ? q.at("q") : "");
  const auto act = lower(q.count("action") ? q.at("action") : "");
  const auto res = lower(q.count("result") ? q.at("result") : "");
  const auto host = lower(q.count("host") ? q.at("host") : "");

  std::vector<audit::AuditEvent> out;
  for (auto it = logs.rbegin(); it != logs.rend() && static_cast<int>(out.size()) < limit; ++it) {
    const auto& e = *it;
    const auto ehost = lower(e.host);
    const auto text = lower(e.url + " " + e.host + " " + e.filename + " " + e.signature);
    if (!act.empty() && lower(e.action) != act) continue;
    if (!res.empty() && lower(e.result) != res) continue;
    if (!host.empty() && ehost.find(host) == std::string::npos) continue;
    if (!word.empty() && text.find(word) == std::string::npos) continue;
    out.push_back(e);
  }
  std::reverse(out.begin(), out.end());
  return out;
}
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
      char buf[65536] = {0};
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
      auto pure_path = path.substr(0, path.find('?'));

      std::string resp;
      if (pure_path == "/healthz" || pure_path == "/readyz") {
        resp = http_resp(200, "OK", "ok", "text/plain");
      } else if (pure_path == "/metrics") {
        resp = http_resp(200, "OK", runtime_.stats.to_metrics_text(), "text/plain");
      } else if (pure_path == "/login" && method == "GET") {
        std::string body = "<html><body><h2>OpenScanProxy Login</h2><form method='POST' action='/login'>"
                           "<input name='u' placeholder='username'/><input type='password' name='p' placeholder='password'/>"
                           "<button type='submit'>Login</button></form></body></html>";
        resp = http_resp(200, "OK", body);
      } else if (pure_path == "/login" && method == "POST") {
        auto form = parse_form(get_body(req));
        const auto u = form.count("u") ? form["u"] : "";
        const auto p = form.count("p") ? form["p"] : "";
        bool ok = u == runtime_.config.admin_user && p == runtime_.config.admin_password;
        if (ok) {
          resp = http_resp(302, "Found", "", "text/plain", "Set-Cookie: session=ok; HttpOnly\r\nLocation: /\r\n");
        } else {
          resp = http_resp(401, "Unauthorized", "bad credentials", "text/plain");
        }
      } else if (pure_path == "/logout") {
        resp = http_resp(302, "Found", "", "text/plain",
                         "Set-Cookie: session=; Max-Age=0; HttpOnly\r\nLocation: /login\r\n");
      } else if (!logged_in(req)) {
        resp = http_resp(302, "Found", "", "text/plain", "Location: /login\r\n");
      } else if (pure_path == "/") {
        resp = http_resp(200, "OK", admin_shell_html());
      } else if (pure_path == "/logs") {
        auto logs = runtime_.audit.latest(100);
        std::ostringstream body;
        body << "<html><body><h2>Audit Logs</h2><table border='1'><tr><th>time</th><th>url</th><th>file</th><th>sha256</th><th>result</th><th>action</th><th>sig</th></tr>";
        for (const auto& e : logs) {
          body << "<tr><td>" << esc(e.timestamp) << "</td><td>" << esc(e.url) << "</td><td>" << esc(e.filename) << "</td><td>"
               << esc(e.sha256) << "</td><td>" << esc(e.result) << "</td><td>" << esc(e.action) << "</td><td>" << esc(e.signature)
               << "</td></tr>";
        }
        body << "</table></body></html>";
        resp = http_resp(200, "OK", body.str());
      } else if (pure_path == "/api/stats") {
        resp = http_resp(200, "OK", stats_to_json(runtime_.stats.snapshot()), "application/json");
      } else if (pure_path == "/api/config") {
        resp = http_resp(200, "OK", config_to_json(runtime_), "application/json");
      } else if (pure_path == "/api/logs") {
        auto logs = filter_logs(runtime_.audit.latest(1000), parse_query(path));
        resp = http_resp(200, "OK", logs_to_json(logs), "application/json");
      } else if (pure_path == "/api/policy" && method == "GET") {
        auto p = runtime_.policy.config();
        std::ostringstream body;
        body << "{\"fail_open\":" << (p.fail_open ? "true" : "false") << ",\"block_suspicious\":"
             << (p.block_suspicious ? "true" : "false") << "}";
        resp = http_resp(200, "OK", body.str(), "application/json");
      } else if (pure_path == "/api/policy" && method == "POST") {
        auto kv = core::parse_simple_json_object(get_body(req));
        auto p = runtime_.policy.config();
        if (kv.count("fail_open")) p.fail_open = kv["fail_open"] == "true";
        if (kv.count("block_suspicious")) p.block_suspicious = kv["block_suspicious"] == "true";
        runtime_.policy.update(p);
        runtime_.config.policy_mode = p.fail_open ? "fail-open" : "fail-close";
        runtime_.config.suspicious_action = p.block_suspicious ? "block" : "log";
        resp = http_resp(200, "OK", "{\"ok\":true}", "application/json");
      } else {
        resp = http_resp(404, "Not Found", "not found", "text/plain");
      }
      send(c, resp.data(), resp.size(), 0);
      close(c);
    }).detach();
  }
}

}  // namespace openscanproxy::admin
