#include "ForensicImageExtractor/utils/HashCalculator.h"

int runHashCalculationTests() {
  const auto sha = fie::utils::HashCalculator::sha256("abc");
  return sha.startsWith("ba7816") ? 0 : 1;
}
