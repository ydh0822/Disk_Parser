#include "ForensicImageExtractor/utils/PathUtils.h"

int runPathUtilsTests() {
  if (fie::utils::sanitizePathComponent("te:st") != "te_st") return 1;
  if (fie::utils::sanitizePathComponent("") != "_") return 1;
  return 0;
}
