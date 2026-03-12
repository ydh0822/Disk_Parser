#include "ForensicImageExtractor/gui/CorrelationUtils.h"

int runCorrelationUtilsTests() {
  using fie::gui::PathCorrelationType;
  using fie::gui::pathCorrelation;
  using fie::gui::pathCorrelationRank;
  using fie::gui::pathCorrelationTypeLabel;
  using fie::gui::pathsCorrelate;

  const auto exact = pathCorrelation("/Users/Alice/NTUSER.DAT", "/Users/Alice/NTUSER.DAT");
  if (!pathsCorrelate("/Users/Alice/NTUSER.DAT", "/Users/Alice/NTUSER.DAT")) return 1;
  if (!exact.correlated() || exact.type != PathCorrelationType::Exact || exact.rank != 0) return 1;
  if (pathCorrelationRank("/Users/Alice/NTUSER.DAT", "/Users/Alice/NTUSER.DAT") != 0) return 1;
  if (pathCorrelationTypeLabel(exact.type) != "exact path") return 1;

  const auto ancestor = pathCorrelation("/Users/Alice/AppData/Roaming", "/Users/Alice/AppData");
  if (!pathsCorrelate("/Users/Alice/AppData/Roaming", "/Users/Alice/AppData")) return 1;
  if (!ancestor.correlated() || ancestor.type != PathCorrelationType::ArtifactAncestor || ancestor.rank != 1) return 1;
  if (pathCorrelationRank("/Users/Alice/AppData/Roaming", "/Users/Alice/AppData") != 1) return 1;

  const auto descendant = pathCorrelation("/Users/Alice", "/Users/Alice/Recent");
  if (!pathsCorrelate("/Users/Alice", "/Users/Alice/Recent")) return 1;
  if (!descendant.correlated() || descendant.type != PathCorrelationType::ArtifactDescendant || descendant.rank != 2) return 1;
  if (pathCorrelationRank("/Users/Alice", "/Users/Alice/Recent") != 2) return 1;

  const auto unrelated = pathCorrelation("/Windows/System32", "/Users/Alice");
  if (pathsCorrelate("/Windows/System32", "/Users/Alice")) return 1;
  if (unrelated.correlated() || unrelated.type != PathCorrelationType::None || unrelated.rank != 100) return 1;
  if (pathCorrelationRank("/Windows/System32", "/Users/Alice") != 100) return 1;
  if (pathCorrelationTypeLabel(unrelated.type) != "none") return 1;

  if (pathsCorrelate("", "/Users/Alice")) return 1;
  if (pathCorrelation("", "/Users/Alice").correlated()) return 1;

  return 0;
}
