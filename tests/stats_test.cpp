#include "openscanproxy/stats/stats.hpp"

#include <iostream>
#include <string>

namespace {

bool expect(bool v, const std::string& msg) {
  if (!v) std::cerr << "FAIL: " << msg << "\n";
  return v;
}

bool contains_line(const std::string& text, const std::string& line) {
  return text.find(line + "\n") != std::string::npos;
}

bool test_snapshot_tracks_incremented_counters() {
  openscanproxy::stats::StatsRegistry stats;
  stats.inc_total_requests();
  stats.inc_total_requests();
  stats.inc_https_mitm_requests();
  stats.inc_scanned_files();
  stats.inc_clean();
  stats.inc_infected();
  stats.inc_suspicious();
  stats.inc_blocked();
  stats.inc_scanner_error();

  const auto snapshot = stats.snapshot();
  return expect(snapshot.total_requests == 2, "total requests counted") &&
         expect(snapshot.https_mitm_requests == 1, "https mitm requests counted") &&
         expect(snapshot.scanned_files == 1, "scanned files counted") &&
         expect(snapshot.clean == 1, "clean counted") &&
         expect(snapshot.infected == 1, "infected counted") &&
         expect(snapshot.suspicious == 1, "suspicious counted") &&
         expect(snapshot.blocked == 1, "blocked counted") &&
         expect(snapshot.scanner_error == 1, "scanner error counted");
}

bool test_metrics_text_reports_all_counters() {
  openscanproxy::stats::StatsRegistry stats;
  stats.inc_total_requests();
  stats.inc_total_requests();
  stats.inc_https_mitm_requests();
  stats.inc_scanned_files();
  stats.inc_clean();
  stats.inc_blocked();

  const auto metrics = stats.to_metrics_text();
  return expect(contains_line(metrics, "total_requests 2"), "metrics include total_requests") &&
         expect(contains_line(metrics, "https_mitm_requests 1"), "metrics include https_mitm_requests") &&
         expect(contains_line(metrics, "scanned_files 1"), "metrics include scanned_files") &&
         expect(contains_line(metrics, "clean 1"), "metrics include clean") &&
         expect(contains_line(metrics, "infected 0"), "metrics include infected zero") &&
         expect(contains_line(metrics, "suspicious 0"), "metrics include suspicious zero") &&
         expect(contains_line(metrics, "blocked 1"), "metrics include blocked") &&
         expect(contains_line(metrics, "scanner_error 0"), "metrics include scanner_error zero");
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_snapshot_tracks_incremented_counters() && ok;
  ok = test_metrics_text_reports_all_counters() && ok;
  if (ok) {
    std::cout << "All stats tests passed\n";
    return 0;
  }
  return 1;
}
