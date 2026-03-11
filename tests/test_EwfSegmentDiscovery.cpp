#include "ForensicImageExtractor/core/EwfSegmentResolver.h"

int runEwfSegmentDiscoveryTests() {
  const QString seed = "C:/cases/disk.E02";
  const QStringList files = {"disk.E01", "disk.E02", "disk.E03", "disk.EX01", "other.E01"};
  QString warning;
  const auto out = fie::core::discoverEwfSegments(seed, files, &warning);
  if (out.size() != 3) return 1;
  if (!out[0].endsWith("disk.E01") || !out[1].endsWith("disk.E02") || !out[2].endsWith("disk.E03")) return 1;
  if (!warning.isEmpty()) return 1;

  const QStringList gapFiles = {"disk.E01", "disk.E03"};
  const auto gapOut = fie::core::discoverEwfSegments("C:/cases/disk.E03", gapFiles, &warning);
  if (gapOut.size() != 2) return 1;
  if (warning.isEmpty() || !warning.contains("2")) return 1;

  if (!fie::core::isEwfPath("x.EX02")) return 1;
  if (!fie::core::isEwfPath("x.S01")) return 1;
  if (fie::core::isEwfPath("x.dd")) return 1;
  return 0;
}
