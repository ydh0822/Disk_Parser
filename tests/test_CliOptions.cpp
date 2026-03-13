#include "ForensicImageExtractor/cli/CliOptions.h"

int runCliOptionsTests() {
  fie::cli::ParsedOptions opt;
  QString error;

  if (!fie::cli::parseOptions({"inspect", "--image", "disk.E01"}, opt, error)) {
    return 1;
  }
  if (opt.command != fie::cli::CommandType::Inspect || opt.imagePath != "disk.E01" || opt.allowPathFallback) {
    return 1;
  }

  error.clear();
  if (!fie::cli::parseOptions({"catalog", "--image", "disk.E01", "--partition", "p2", "--source", "/Users", "--dest", "out", "--catalog-out", "catalog.json", "--catalog-format", "json", "--overwrite", "versioned", "--md5", "--apply-host-timestamps"}, opt, error)) {
    return 1;
  }
  if (opt.command != fie::cli::CommandType::Catalog || opt.partition != "p2" || opt.catalogFormat != "json" ||
      opt.overwriteMode != fie::domain::OverwriteMode::VersionedCopy || !opt.computeMd5 ||
      !opt.applyHostTimestamps) {
    return 1;
  }

  error.clear();
  if (fie::cli::parseOptions({"catalog", "--image", "disk.E01", "--source", "/", "--dest", "out"}, opt,
                             error) ||
      error.isEmpty()) {
    return 1;
  }


  error.clear();
  if (!fie::cli::parseOptions({"artifacts", "scan", "--image", "disk.E01", "--partition", "p1"}, opt, error)) {
    return 1;
  }
  if (opt.command != fie::cli::CommandType::ArtifactsScan || opt.partition != "p1") {
    return 1;
  }

  error.clear();
  if (fie::cli::parseOptions({"artifacts", "scan", "--image", "disk.E01", "--partition", ""}, opt, error) ||
      error.isEmpty()) {
    return 1;
  }

  error.clear();
  if (fie::cli::parseOptions({"extract", "--image", "disk.E01", "--source", "/", "--dest", "out", "--overwrite", "invalid"}, opt, error) ||
      error != "Invalid overwrite mode") {
    return 1;
  }

  return 0;
}
