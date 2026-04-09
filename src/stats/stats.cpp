#include "openscanproxy/stats/stats.hpp"

#include <sstream>

namespace openscanproxy::stats {

Snapshot StatsRegistry::snapshot() const {
  return Snapshot{total_requests_.load(), https_mitm_requests_.load(), scanned_files_.load(), clean_.load(),
                  infected_.load(), suspicious_.load(), blocked_.load(), scanner_error_.load()};
}

std::string StatsRegistry::to_metrics_text() const {
  auto s = snapshot();
  std::ostringstream os;
  os << "total_requests " << s.total_requests << "\n"
     << "https_mitm_requests " << s.https_mitm_requests << "\n"
     << "scanned_files " << s.scanned_files << "\n"
     << "clean " << s.clean << "\n"
     << "infected " << s.infected << "\n"
     << "suspicious " << s.suspicious << "\n"
     << "blocked " << s.blocked << "\n"
     << "scanner_error " << s.scanner_error << "\n";
  return os.str();
}

}  // namespace openscanproxy::stats
