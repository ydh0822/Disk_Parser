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
  tree["/Windows/System32"] = {FileEntry{.name = "Tasks", .fullPath = "/Windows/System32/Tasks", .isDirectory = true}};
  tree["/Windows/System32/Tasks"] = {
      FileEntry{.name = "Microsoft", .fullPath = "/Windows/System32/Tasks/Microsoft", .isDirectory = true},
      FileEntry{.name = "StandaloneTask", .fullPath = "/Windows/System32/Tasks/StandaloneTask", .sizeBytes = 100},
  };
  tree["/Windows/System32/Tasks/Microsoft"] = {
      FileEntry{.name = "Windows", .fullPath = "/Windows/System32/Tasks/Microsoft/Windows", .isDirectory = true},
  };
  tree["/Windows/System32/Tasks/Microsoft/Windows"] = {
      FileEntry{.name = "Defrag", .fullPath = "/Windows/System32/Tasks/Microsoft/Windows/Defrag", .sizeBytes = 200},
  };
  tree["/Users/Alice/AppData/Roaming/Microsoft/Windows/Recent"] = {
      FileEntry{.name = "Doc.lnk", .fullPath = "/Users/Alice/AppData/Roaming/Microsoft/Windows/Recent/Doc.lnk", .sizeBytes = 12},
      FileEntry{.name = "Auto.automaticDestinations-ms", .fullPath = "/Users/Alice/AppData/Roaming/Microsoft/Windows/Recent/Auto.automaticDestinations-ms", .sizeBytes = 34},
  };
  tree["/ProgramData/Microsoft/Windows/WER"] = {
      FileEntry{.name = "ReportQueue", .fullPath = "/ProgramData/Microsoft/Windows/WER/ReportQueue", .isDirectory = true},
  };
  tree["/ProgramData/Microsoft/Windows/WER/ReportQueue"] = {
      FileEntry{.name = "AppCrash_Test", .fullPath = "/ProgramData/Microsoft/Windows/WER/ReportQueue/AppCrash_Test", .isDirectory = true},
  };
  tree["/ProgramData/Microsoft/Windows/WER/ReportQueue/AppCrash_Test"] = {
      FileEntry{.name = "Report.wer", .fullPath = "/ProgramData/Microsoft/Windows/WER/ReportQueue/AppCrash_Test/Report.wer", .sizeBytes = 222},
  };
  tree["/Windows/System32/winevt"] = {
      FileEntry{.name = "Logs", .fullPath = "/Windows/System32/winevt/Logs", .isDirectory = true},
  };
  tree["/Windows/System32/winevt/Logs"] = {
      FileEntry{.name = "Security.evtx", .fullPath = "/Windows/System32/winevt/Logs/Security.evtx", .sizeBytes = 4000},
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
  bool sawAppCompatResolver = false;
  bool sawScheduledTaskDefinition = false;
  bool sawWerDefinition = false;
  bool sawEvtxDefinition = false;
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
    if (artifact.artifactName == "AppCompatCache resolver" && artifact.status == "Missing") {
      sawAppCompatResolver = true;
    }
    if (artifact.artifactName == "Scheduled Task definitions" &&
        artifact.sourceLogicalPath == "/Windows/System32/Tasks/StandaloneTask") {
      sawScheduledTaskDefinition = true;
    }
    if (artifact.artifactName == "WER report files" &&
        artifact.sourceLogicalPath == "/ProgramData/Microsoft/Windows/WER/ReportQueue/AppCrash_Test/Report.wer") {
      sawWerDefinition = true;
    }
    if (artifact.artifactName == "EVTX files" &&
        artifact.sourceLogicalPath == "/Windows/System32/winevt/Logs/Security.evtx") {
      sawEvtxDefinition = true;
    }
  }

  if (!sawChromeHistory || !sawLnk || !sawMissingWithoutWarning || !sawDirectoryTarget || !sawAppCompatResolver ||
      !sawScheduledTaskDefinition || !sawWerDefinition || !sawEvtxDefinition) {
    return 1;
  }
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
