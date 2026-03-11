#include "ForensicImageExtractor/utils/ExtractionPlanner.h"

int runChunkPlanTests() {
  const auto p = fie::utils::buildChunkPlan(10, 4);
  if (p.size() != 3 || p[0] != 4 || p[1] != 4 || p[2] != 2) return 1;

  const auto z = fie::utils::buildChunkPlan(0, 4);
  if (z.size() != 1 || z[0] != 0) return 1;

  return 0;
}
