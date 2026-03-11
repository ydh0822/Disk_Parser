#include "ForensicImageExtractor/utils/ExtractionPlanner.h"

int runRecursiveVisitedHandlingTests() {
  const QStringList in = {"/a", "/b", "/a", "/c", "/b"};
  const auto out = fie::utils::deduplicateOrderedPaths(in);
  if (out.size() != 3) return 1;
  if (out[0] != "/a" || out[1] != "/b" || out[2] != "/c") return 1;
  return 0;
}
