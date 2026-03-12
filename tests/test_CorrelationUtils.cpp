#include "ForensicImageExtractor/gui/CorrelationUtils.h"

int runCorrelationUtilsTests() {
  using fie::gui::pathCorrelationRank;
  using fie::gui::pathsCorrelate;

  if (!pathsCorrelate("/Users/Alice/NTUSER.DAT", "/Users/Alice/NTUSER.DAT")) return 1;
  if (pathCorrelationRank("/Users/Alice/NTUSER.DAT", "/Users/Alice/NTUSER.DAT") != 0) return 1;

  if (!pathsCorrelate("/Users/Alice/AppData/Roaming", "/Users/Alice/AppData")) return 1;
  if (pathCorrelationRank("/Users/Alice/AppData/Roaming", "/Users/Alice/AppData") != 1) return 1;

  if (!pathsCorrelate("/Users/Alice", "/Users/Alice/Recent")) return 1;
  if (pathCorrelationRank("/Users/Alice", "/Users/Alice/Recent") != 2) return 1;

  if (pathsCorrelate("/Windows/System32", "/Users/Alice")) return 1;
  if (pathCorrelationRank("/Windows/System32", "/Users/Alice") != 100) return 1;

  return 0;
}
