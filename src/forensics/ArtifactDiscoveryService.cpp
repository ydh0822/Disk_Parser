#include "ForensicImageExtractor/forensics/ArtifactDiscoveryService.h"

#include <QSet>

namespace fie::forensics {
namespace {

struct ArtifactRule {
  QString category;
  QString name;
  QString pathTemplate;
  bool perProfile{false};
  bool directoryTarget{false};
  QString notes;
};

struct EntryLookup {
  bool found{false};
  bool failed{false};
  domain::FileEntry entry;
};

bool isCancelled(const ArtifactDiscoveryService::IsCancelledFn &fn) {
  return fn && fn();
}

QString normalizePath(const QString &path) {
  auto out = path;
  out.replace('\\', '/');
  if (!out.startsWith('/')) out.prepend('/');
  while (out.contains("//")) out.replace("//", "/");
  if (out.size() > 1 && out.endsWith('/')) out.chop(1);
  return out;
}

QString parentPath(const QString &path) {
  const auto normalized = normalizePath(path);
  const int slash = normalized.lastIndexOf('/');
  if (slash <= 0) return "/";
  return normalized.left(slash);
}

QString baseName(const QString &path) {
  const auto normalized = normalizePath(path);
  const int slash = normalized.lastIndexOf('/');
  return slash < 0 ? normalized : normalized.mid(slash + 1);
}

EntryLookup findEntry(const ArtifactDiscoveryService::ListDirectoryFn &listDirectory, const QString &fullPath,
                      const QString &warningContext, QStringList &warnings) {
  QString error;
  const auto entries = listDirectory(parentPath(fullPath), error);
  if (!error.isEmpty()) {
    // Resolver checks should not treat missing paths as warnings unless context indicates
    // an already-traversed tree failed unexpectedly.
    if (!warningContext.isEmpty()) {
      warnings.push_back(QString("%1: %2").arg(warningContext, error));
      return {.found = false, .failed = true, .entry = {}};
    }
    return {};
  }

  const QString name = baseName(fullPath);
  for (const auto &entry : entries) {
    if (entry.name.compare(name, Qt::CaseInsensitive) == 0) return {.found = true, .failed = false, .entry = entry};
  }
  return {};
}

std::vector<QString> enumerateProfiles(const ArtifactDiscoveryService::ListDirectoryFn &listDirectory,
                                       QStringList &warnings,
                                       const ArtifactDiscoveryService::IsCancelledFn &cancel) {
  if (isCancelled(cancel)) return {};
  QString error;
  const auto users = listDirectory("/Users", error);
  if (!error.isEmpty()) {
    warnings.push_back(QString("Profile enumeration failed at /Users: %1").arg(error));
    return {};
  }

  std::vector<QString> profiles;
  const QSet<QString> skip{"all users", "default", "default user", "defaultuser0", "public"};
  for (const auto &entry : users) {
    if (isCancelled(cancel)) return profiles;
    if (!entry.isDirectory) continue;
    if (skip.contains(entry.name.toLower())) continue;
    profiles.push_back(entry.name);
  }
  return profiles;
}

void appendRuleResults(std::vector<domain::ArtifactRecord> &out, const std::vector<ArtifactRule> &rules,
                       const std::vector<QString> &profiles, const domain::PartitionInfo &partition,
                       const ArtifactDiscoveryService::ListDirectoryFn &listDirectory,
                       QStringList &warnings,
                       const ArtifactDiscoveryService::IsCancelledFn &cancel) {
  auto appendRecord = [&](const ArtifactRule &rule, const QString &profile, const QString &resolvedPath) {
    if (isCancelled(cancel)) return;

    domain::ArtifactRecord rec;
    rec.category = rule.category;
    rec.artifactName = rule.name;
    rec.profile = profile;
    rec.sourceLogicalPath = resolvedPath;
    rec.partitionIdentifier = partition.identifier;
    rec.fileSystemType = partition.fileSystemType;
    rec.notes = rule.notes;
    rec.directoryTarget = rule.directoryTarget;

    const auto found = findEntry(listDirectory, resolvedPath, {}, warnings);
    if (found.found) {
      rec.status = "Present";
      rec.sizeBytes = found.entry.sizeBytes;
      rec.keyTimestamp = found.entry.metadata.timestamps.modified;
      if (rule.directoryTarget) {
        rec.notes = rec.notes.isEmpty() ? "Directory target" : rec.notes + " | Directory target";
      }
    } else {
      rec.status = "Missing";
      if (rec.notes.isEmpty()) rec.notes = "Resolver target not present";
    }
    out.push_back(std::move(rec));
  };

  for (const auto &rule : rules) {
    if (isCancelled(cancel)) return;
    if (rule.perProfile) {
      for (const auto &profile : profiles) {
        if (isCancelled(cancel)) return;
        appendRecord(rule, profile, normalizePath(rule.pathTemplate).replace("{user}", profile));
      }
    } else {
      appendRecord(rule, "SYSTEM", normalizePath(rule.pathTemplate));
    }
  }
}

void appendRecursiveBySuffix(std::vector<domain::ArtifactRecord> &out, const QString &category,
                             const QString &artifactName, const QString &profile, const QString &root,
                             const QStringList &suffixes, const domain::PartitionInfo &partition,
                             const ArtifactDiscoveryService::ListDirectoryFn &listDirectory,
                             QStringList &warnings,
                             const ArtifactDiscoveryService::IsCancelledFn &cancel,
                             int maxDepth = 3) {
  if (isCancelled(cancel)) return;

  QString rootError;
  auto rootEntries = listDirectory(normalizePath(root), rootError);
  if (!rootError.isEmpty()) {
    // Root missing is common and expected; suppress warning noise.
    return;
  }

  struct Node {
    QString path;
    int depth;
    std::vector<domain::FileEntry> entries;
  };

  std::vector<Node> stack;
  stack.push_back({normalizePath(root), 0, std::move(rootEntries)});
  while (!stack.empty()) {
    if (isCancelled(cancel)) return;
    auto node = std::move(stack.back());
    stack.pop_back();

    for (const auto &entry : node.entries) {
      if (isCancelled(cancel)) return;

      if (entry.isDirectory && node.depth < maxDepth) {
        QString childError;
        auto children = listDirectory(entry.fullPath, childError);
        if (!childError.isEmpty()) {
          warnings.push_back(QString("Artifact traversal failed at '%1': %2").arg(entry.fullPath, childError));
          continue;
        }
        stack.push_back({entry.fullPath, node.depth + 1, std::move(children)});
        continue;
      }
      if (entry.isDirectory) continue;

      const auto lower = entry.name.toLower();
      bool match = false;
      for (const auto &suffix : suffixes) {
        if (lower.endsWith(suffix.toLower())) {
          match = true;
          break;
        }
      }
      if (!match) continue;

      domain::ArtifactRecord rec;
      rec.category = category;
      rec.artifactName = artifactName;
      rec.profile = profile;
      rec.sourceLogicalPath = entry.fullPath;
      rec.status = "Present";
      rec.sizeBytes = entry.sizeBytes;
      rec.keyTimestamp = entry.metadata.timestamps.modified;
      rec.partitionIdentifier = partition.identifier;
      rec.fileSystemType = partition.fileSystemType;
      rec.directoryTarget = false;
      out.push_back(std::move(rec));
    }
  }
}

} // namespace

std::vector<domain::ArtifactRecord> ArtifactDiscoveryService::discover(
    const domain::PartitionInfo &partition, const ListDirectoryFn &listDirectory, QStringList &warnings,
    const IsCancelledFn &isCancelledFn) const {
  std::vector<domain::ArtifactRecord> out;
  if (!listDirectory) {
    warnings.push_back("Artifact discovery skipped: no directory listing callback");
    return out;
  }

  const auto profiles = enumerateProfiles(listDirectory, warnings, isCancelledFn);
  if (isCancelled(isCancelledFn)) return out;

  const std::vector<ArtifactRule> rules{
      {"Browser", "Chrome History", "/Users/{user}/AppData/Local/Google/Chrome/User Data/Default/History", true, false, "SQLite parsing deferred"},
      {"Browser", "Edge History", "/Users/{user}/AppData/Local/Microsoft/Edge/User Data/Default/History", true, false, "SQLite parsing deferred"},
      {"Browser", "Downloads", "/Users/{user}/Downloads", true, true, {}},
      {"Browser", "Cookies", "/Users/{user}/AppData/Local/Google/Chrome/User Data/Default/Cookies", true, false, {}},
      {"Browser", "Login Data", "/Users/{user}/AppData/Local/Google/Chrome/User Data/Default/Login Data", true, false, "Existence check only"},
      {"Execution", "Prefetch", "/Windows/Prefetch", false, true, {}},
      {"Execution", "Amcache", "/Windows/AppCompat/Programs/Amcache.hve", false, false, {}},
      {"Execution", "RecentDocs resolver", "/Users/{user}/NTUSER.DAT", true, false, "Registry hive target only"},
      {"Execution", "UserAssist resolver", "/Users/{user}/NTUSER.DAT", true, false, "Registry hive target only"},
      {"Persistence", "Run/RunOnce resolver", "/Users/{user}/NTUSER.DAT", true, false, "Registry hive target only"},
      {"Persistence", "Startup folder", "/Users/{user}/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup", true, true, {}},
      {"Persistence", "Scheduled Tasks", "/Windows/System32/Tasks", false, true, {}},
      {"Persistence", "Services hive resolver", "/Windows/System32/config/SYSTEM", false, false, "Registry hive target only"},
      {"External", "Recycle Bin", "/$Recycle.Bin", false, true, {}},
      {"External", "USB registry resolver", "/Windows/System32/config/SYSTEM", false, false, "Registry hive target only"},
      {"Event/System", "EVTX root", "/Windows/System32/winevt/Logs", false, true, {}},
      {"Event/System", "SRUM", "/Windows/System32/sru/SRUDB.dat", false, false, "Existence check only"},
      {"Event/System", "WER", "/ProgramData/Microsoft/Windows/WER", false, true, "Existence check only"},
  };

  appendRuleResults(out, rules, profiles, partition, listDirectory, warnings, isCancelledFn);
  if (isCancelled(isCancelledFn)) return out;

  for (const auto &profile : profiles) {
    appendRecursiveBySuffix(out, "External", "LNK files", profile,
                            QString("/Users/%1/AppData/Roaming/Microsoft/Windows/Recent").arg(profile),
                            {".lnk"}, partition, listDirectory, warnings, isCancelledFn, 2);
    appendRecursiveBySuffix(out, "External", "Jump Lists", profile,
                            QString("/Users/%1/AppData/Roaming/Microsoft/Windows/Recent").arg(profile),
                            {".automaticdestinations-ms", ".customdestinations-ms"}, partition, listDirectory,
                            warnings, isCancelledFn, 3);
    if (isCancelled(isCancelledFn)) return out;
  }

  return out;
}

} // namespace fie::forensics
