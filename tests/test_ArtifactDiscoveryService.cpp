#include "ForensicImageExtractor/forensics/ArtifactDiscoveryService.h"

#include <QHash>

int runArtifactDiscoveryServiceTests() {
  using fie::domain::FileEntry;
  using fie::forensics::ArtifactDiscoveryService;

  QHash<QString, std::vector<FileEntry>> tree;
  tree["/Users"] = {
      FileEntry{.name = "Alice", .fullPath = "/Users/Alice", .isDirectory = true},
      FileEntry{.name = "Public", .fullPath = "/Users/Public", .isDirectory = true},
  };
  tree["/Users/Alice/AppData/Local/Google/Chrome/User Data/Default"] = {
      FileEntry{.name = "History", .fullPath = "/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/History", .sizeBytes = 1234},
  };
  tree["/Windows"] = {FileEntry{.name = "Prefetch", .fullPath = "/Windows/Prefetch", .isDirectory = true}};
  tree["/Windows/Prefetch"] = {FileEntry{.name = "APP.EXE-111.pf", .fullPath = "/Windows/Prefetch/APP.EXE-111.pf", .sizeBytes = 456}};
  tree["/Users/Alice/AppData/Roaming/Microsoft/Windows/Recent"] = {
      FileEntry{.name = "Doc.lnk", .fullPath = "/Users/Alice/AppData/Roaming/Microsoft/Windows/Recent/Doc.lnk", .sizeBytes = 12},
      FileEntry{.name = "Auto.automaticDestinations-ms", .fullPath = "/Users/Alice/AppData/Roaming/Microsoft/Windows/Recent/Auto.automaticDestinations-ms", .sizeBytes = 34},
  };

  ArtifactDiscoveryService service;
  fie::domain::PartitionInfo partition;
  partition.identifier = "p0";
  partition.fileSystemType = "NTFS";
  QStringList warnings;
  const auto artifacts = service.discover(
      partition,
      [&tree](const QString &path, QString &error) {
        error.clear();
        if (!tree.contains(path)) {
          error = "missing synthetic dir";
          return std::vector<FileEntry>{};
        }
        return tree[path];
      },
      warnings);

  if (artifacts.empty()) return 1;

  bool sawChromeHistory = false;
  bool sawLnk = false;
  bool sawMissingWithoutWarning = false;
  bool sawDirectoryTarget = false;
  for (const auto &artifact : artifacts) {
    if (artifact.artifactName == "Chrome History" && artifact.profile == "Alice" && artifact.status == "Present") {
      sawChromeHistory = true;
    }
    if (artifact.artifactName == "LNK files" && artifact.sourceLogicalPath.endsWith(".lnk")) {
      sawLnk = true;
    }
    if (artifact.artifactName == "Edge History" && artifact.status == "Missing") {
      sawMissingWithoutWarning = true;
    }
    if (artifact.artifactName == "Prefetch" && artifact.status == "Present" && artifact.directoryTarget) {
      sawDirectoryTarget = true;
    }
  }

  if (!sawChromeHistory || !sawLnk || !sawMissingWithoutWarning || !sawDirectoryTarget) return 1;
  if (!warnings.isEmpty()) return 1; // missing resolver targets should not be warnings

  bool cancel = false;
  warnings.clear();
  const auto cancelledArtifacts = service.discover(
      partition,
      [&tree](const QString &path, QString &error) {
        error.clear();
        if (!tree.contains(path)) {
          error = "missing synthetic dir";
          return std::vector<FileEntry>{};
        }
        return tree[path];
      },
      warnings,
      [&cancel]() { return cancel; });
  if (cancelledArtifacts.empty()) return 1;

  cancel = true;
  const auto stopped = service.discover(
      partition,
      [&tree](const QString &path, QString &error) {
        error.clear();
        if (!tree.contains(path)) {
          error = "missing synthetic dir";
          return std::vector<FileEntry>{};
        }
        return tree[path];
      },
      warnings,
      [&cancel]() { return cancel; });
  if (!stopped.empty()) return 1;

  return 0;
}
