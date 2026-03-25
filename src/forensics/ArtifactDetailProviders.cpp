#include "ForensicImageExtractor/forensics/ArtifactDetailProviders.h"
#include "ForensicImageExtractor/forensics/ArtifactMaterializationService.h"
#include "ForensicImageExtractor/forensics/RegistryHive.h"

#include <QStringDecoder>
#include <algorithm>
#if defined(FIE_HAS_SQLITE)
#include <sqlite3.h>
#endif

namespace fie::forensics {
namespace {

constexpr quint32 kLnkHeaderSize = 0x4C;

quint16 readLe16(const QByteArray &bytes, int off, bool *ok = nullptr) {
  if (off < 0 || off + 2 > bytes.size()) {
    if (ok) *ok = false;
    return 0;
  }
  if (ok) *ok = true;
  return static_cast<quint16>(static_cast<quint8>(bytes[off])) |
         (static_cast<quint16>(static_cast<quint8>(bytes[off + 1])) << 8);
}

quint32 readLe32(const QByteArray &bytes, int off, bool *ok = nullptr) {
  if (off < 0 || off + 4 > bytes.size()) {
    if (ok) *ok = false;
    return 0;
  }
  if (ok) *ok = true;
  return static_cast<quint32>(static_cast<quint8>(bytes[off])) |
         (static_cast<quint32>(static_cast<quint8>(bytes[off + 1])) << 8) |
         (static_cast<quint32>(static_cast<quint8>(bytes[off + 2])) << 16) |
         (static_cast<quint32>(static_cast<quint8>(bytes[off + 3])) << 24);
}

quint64 readLe64(const QByteArray &bytes, int off, bool *ok = nullptr) {
  if (off < 0 || off + 8 > bytes.size()) {
    if (ok) *ok = false;
    return 0;
  }
  quint64 value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<quint64>(static_cast<quint8>(bytes[off + i])) << (8 * i);
  }
  if (ok) *ok = true;
  return value;
}

std::optional<QDateTime> filetimeToUtc(quint64 filetime) {
  if (filetime == 0) return std::nullopt;
  constexpr qint64 kTicksPerSecond = 10000000LL;
  constexpr qint64 kWindowsToUnixEpochSeconds = 11644473600LL;
  const qint64 sec = static_cast<qint64>(filetime / kTicksPerSecond) - kWindowsToUnixEpochSeconds;
  if (sec <= 0) return std::nullopt;
  return QDateTime::fromSecsSinceEpoch(sec, Qt::UTC);
}

QString decodeUtf16Le(const QByteArray &bytes) {
  QStringDecoder decoder(QStringDecoder::Utf16LE);
  QString text = decoder.decode(bytes);
  const int nullPos = text.indexOf(QChar('\0'));
  if (nullPos >= 0) text = text.left(nullPos);
  return text;
}

QString readNullTerminatedAnsi(const QByteArray &bytes, int off) {
  if (off < 0 || off >= bytes.size()) return {};
  int end = off;
  while (end < bytes.size() && bytes[end] != '\0') ++end;
  return QString::fromLatin1(bytes.constData() + off, end - off);
}

std::vector<QString> parseMruOrder(const RegistryHive::Key &key) {
  std::vector<QString> out;
  for (const auto &value : key.values) {
    if (value.name.compare("MRUList", Qt::CaseInsensitive) == 0) {
      const QString s = QString::fromLatin1(value.rawData).trimmed();
      for (const auto ch : s) out.push_back(QString(ch));
      return out;
    }
    if (value.name.compare("MRUListEx", Qt::CaseInsensitive) == 0) {
      for (int i = 0; i + 4 <= value.rawData.size(); i += 4) {
        bool ok = false;
        const quint32 slot = readLe32(value.rawData, i, &ok);
        if (!ok || slot == 0xFFFFFFFF) break;
        out.push_back(QString::number(slot));
      }
      return out;
    }
  }
  return out;
}

std::optional<int> mruPos(const std::vector<QString> &order, const QString &valueName) {
  for (int i = 0; i < static_cast<int>(order.size()); ++i) {
    if (order[i].compare(valueName, Qt::CaseInsensitive) == 0) return i;
  }
  return std::nullopt;
}

const RegistryHive::Value *findValueCi(const RegistryHive::Key &key, const QString &name) {
  for (const auto &value : key.values) {
    if (value.name.compare(name, Qt::CaseInsensitive) == 0) return &value;
  }
  return nullptr;
}

std::optional<QDateTime> decodeFiletimeBlob(const QByteArray &blob) {
  if (blob.size() < 8) return std::nullopt;
  const auto first = filetimeToUtc(readLe64(blob, 0));
  if (first.has_value()) return first;
  if (blob.size() >= 16) return filetimeToUtc(readLe64(blob, blob.size() - 8));
  return std::nullopt;
}

QString resolveControlSetPathPrefix(const RegistryHive &hive, QStringList &warnings) {
  QString error;
  const auto select = hive.keyByPath("Select", error);
  if (!select.has_value()) {
    warnings.push_back("SYSTEM Select\\Current was unavailable; using ControlSet001");
    return "ControlSet001";
  }
  const auto *current = findValueCi(*select, "Current");
  if (!current) {
    warnings.push_back("SYSTEM Select\\Current was unavailable; using ControlSet001");
    return "ControlSet001";
  }
  const auto currentId = decodeRegistryDword(*current);
  if (!currentId.has_value()) {
    warnings.push_back("SYSTEM Select\\Current was invalid; using ControlSet001");
    return "ControlSet001";
  }
  return QString("ControlSet%1").arg(*currentId, 3, 10, QChar('0'));
}

QString decodeUserAssistName(const QString &encoded) {
  QString out = encoded;
  for (int i = 0; i < out.size(); ++i) {
    const QChar c = out[i];
    if (c >= 'a' && c <= 'z') {
      out[i] = QChar('a' + ((c.unicode() - 'a' + 13) % 26));
    } else if (c >= 'A' && c <= 'Z') {
      out[i] = QChar('A' + ((c.unicode() - 'A' + 13) % 26));
    }
  }
  return out;
}

class RegistryRunMruProvider final : public IArtifactDetailProvider {
public:
  QString name() const override { return "windows.registry_run_mru"; }
  bool supports(const domain::ArtifactRecord &artifact) const override {
    return artifact.artifactName.compare("Run/RunOnce resolver", Qt::CaseInsensitive) == 0 &&
           artifact.sourceLogicalPath.endsWith("NTUSER.DAT", Qt::CaseInsensitive);
  }
  domain::ArtifactDetails parse(const domain::ArtifactRecord &artifact,
                                const ArtifactDetailRequest &request) const override {
    domain::ArtifactDetails out;
    out.provider = name();
    QString error;
    const auto bytes = request.readBytes(artifact.sourceLogicalPath, error);
    if (!error.isEmpty()) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = error;
      out.summary = "Unable to read NTUSER.DAT";
      return out;
    }

    RegistryHive hive;
    if (!hive.open(bytes, error)) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = error;
      out.summary = "RunMRU parse failed";
      return out;
    }

    const auto key = hive.keyByPath("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", error);
    if (!key.has_value()) {
      out.state = domain::ArtifactParseState::Unsupported;
      out.summary = "RunMRU key is not present";
      return out;
    }

    const auto order = parseMruOrder(*key);
    for (const auto &value : key->values) {
      if (value.name.compare("MRUList", Qt::CaseInsensitive) == 0 ||
          value.name.compare("MRUListEx", Qt::CaseInsensitive) == 0) {
        continue;
      }
      domain::ArtifactDetails::RegistryRunMruEntry entry;
      entry.valueName = value.name;
      entry.command = decodeRegistryString(value);
      entry.mruPosition = mruPos(order, value.name);
      out.registryRunMruEntries.push_back(std::move(entry));
    }
    std::stable_sort(out.registryRunMruEntries.begin(), out.registryRunMruEntries.end(),
                     [](const auto &a, const auto &b) {
                       if (a.mruPosition.has_value() != b.mruPosition.has_value()) return a.mruPosition.has_value();
                       if (a.mruPosition && b.mruPosition && a.mruPosition.value() != b.mruPosition.value()) {
                         return a.mruPosition.value() < b.mruPosition.value();
                       }
                       return a.valueName.compare(b.valueName, Qt::CaseInsensitive) < 0;
                     });
    out.state = out.registryRunMruEntries.empty() ? domain::ArtifactParseState::Partial : domain::ArtifactParseState::Parsed;
    out.summary = out.registryRunMruEntries.empty() ? "RunMRU key has no command values" : "RunMRU parsed";
    return out;
  }
};

class RegistryRecentDocsProvider final : public IArtifactDetailProvider {
public:
  QString name() const override { return "windows.registry_recent_docs"; }
  bool supports(const domain::ArtifactRecord &artifact) const override {
    return artifact.artifactName.compare("RecentDocs resolver", Qt::CaseInsensitive) == 0 &&
           artifact.sourceLogicalPath.endsWith("NTUSER.DAT", Qt::CaseInsensitive);
  }
  domain::ArtifactDetails parse(const domain::ArtifactRecord &artifact,
                                const ArtifactDetailRequest &request) const override {
    domain::ArtifactDetails out;
    out.provider = name();
    QString error;
    const auto bytes = request.readBytes(artifact.sourceLogicalPath, error);
    if (!error.isEmpty()) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = error;
      out.summary = "Unable to read NTUSER.DAT";
      return out;
    }
    RegistryHive hive;
    if (!hive.open(bytes, error)) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = error;
      out.summary = "RecentDocs parse failed";
      return out;
    }
    const QString typedPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths";
    const auto typed = hive.keyByPath(typedPath, error);
    if (typed.has_value()) {
      for (const auto &value : typed->values) {
        if (!value.name.startsWith("url", Qt::CaseInsensitive)) continue;
        domain::ArtifactDetails::RegistryTypedPathEntry e;
        e.valueName = value.name;
        e.path = decodeRegistryString(value);
        out.registryTypedPathEntries.push_back(std::move(e));
      }
      std::stable_sort(out.registryTypedPathEntries.begin(), out.registryTypedPathEntries.end(),
                       [](const auto &a, const auto &b) { return a.valueName.compare(b.valueName, Qt::CaseInsensitive) < 0; });
    }

    const QString basePath = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs";
    const auto base = hive.keyByPath(basePath, error);
    if (!base.has_value()) {
      out.state = out.registryTypedPathEntries.empty() ? domain::ArtifactParseState::Unsupported
                                                       : domain::ArtifactParseState::Partial;
      out.summary = out.registryTypedPathEntries.empty() ? "RecentDocs key is not present" : "TypedPaths parsed; RecentDocs key missing";
      return out;
    }

    auto appendFromKey = [&](const RegistryHive::Key &key, const QString &extGroup) {
      const auto order = parseMruOrder(key);
      for (const auto &value : key.values) {
        if (value.name.compare("MRUList", Qt::CaseInsensitive) == 0 ||
            value.name.compare("MRUListEx", Qt::CaseInsensitive) == 0) {
          continue;
        }
        domain::ArtifactDetails::RegistryRecentDocEntry e;
        e.valueName = value.name;
        e.documentName = decodeRegistryString(value);
        e.extensionGroup = extGroup;
        e.mruPosition = mruPos(order, value.name);
        out.registryRecentDocEntries.push_back(std::move(e));
      }
    };

    appendFromKey(*base, "(all)");
    for (const auto &child : hive.childKeys(basePath, error)) {
      const QString ext = child.path.section('\\', -1);
      appendFromKey(child, ext);
    }
    std::stable_sort(out.registryRecentDocEntries.begin(), out.registryRecentDocEntries.end(),
                     [](const auto &a, const auto &b) {
                       if (a.extensionGroup.compare(b.extensionGroup, Qt::CaseInsensitive) != 0) {
                         return a.extensionGroup.compare(b.extensionGroup, Qt::CaseInsensitive) < 0;
                       }
                       if (a.mruPosition.has_value() != b.mruPosition.has_value()) return a.mruPosition.has_value();
                       if (a.mruPosition && b.mruPosition && a.mruPosition.value() != b.mruPosition.value()) {
                         return a.mruPosition.value() < b.mruPosition.value();
                       }
                       return a.valueName.compare(b.valueName, Qt::CaseInsensitive) < 0;
                     });
    const bool hasRecent = !out.registryRecentDocEntries.empty();
    const bool hasTyped = !out.registryTypedPathEntries.empty();
    out.state = (hasRecent || hasTyped) ? domain::ArtifactParseState::Parsed : domain::ArtifactParseState::Partial;
    out.summary = hasRecent ? (hasTyped ? "RecentDocs and TypedPaths parsed" : "RecentDocs parsed")
                            : (hasTyped ? "TypedPaths parsed; RecentDocs has no supported values"
                                        : "RecentDocs key has no supported values");
    return out;
  }
};

class RegistryUserAssistProvider final : public IArtifactDetailProvider {
public:
  QString name() const override { return "windows.registry_userassist"; }
  bool supports(const domain::ArtifactRecord &artifact) const override {
    return artifact.artifactName.compare("UserAssist resolver", Qt::CaseInsensitive) == 0 &&
           artifact.sourceLogicalPath.endsWith("NTUSER.DAT", Qt::CaseInsensitive);
  }
  domain::ArtifactDetails parse(const domain::ArtifactRecord &artifact,
                                const ArtifactDetailRequest &request) const override {
    domain::ArtifactDetails out;
    out.provider = name();
    QString error;
    const auto bytes = request.readBytes(artifact.sourceLogicalPath, error);
    if (!error.isEmpty()) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = error;
      out.summary = "Unable to read NTUSER.DAT";
      return out;
    }
    RegistryHive hive;
    if (!hive.open(bytes, error)) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = error;
      out.summary = "UserAssist parse failed";
      return out;
    }

    const QString uaRoot = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
    const auto guidKeys = hive.childKeys(uaRoot, error);
    if (!error.isEmpty() || guidKeys.empty()) {
      out.state = domain::ArtifactParseState::Unsupported;
      out.summary = "UserAssist key is not present";
      return out;
    }

    for (const auto &guid : guidKeys) {
      const auto countKey = hive.keyByPath(guid.path + "\\Count", error);
      if (!countKey.has_value()) continue;
      for (const auto &value : countKey->values) {
        domain::ArtifactDetails::RegistryUserAssistEntry e;
        e.encodedName = value.name;
        e.decodedName = decodeUserAssistName(value.name);
        if (value.rawData.size() >= 8) {
          e.runCount = readLe32(value.rawData, 4);
        }
        if (value.rawData.size() >= 68) {
          const auto dt = filetimeToUtc(readLe64(value.rawData, 60));
          e.lastExecution = dt;
        }
        out.registryUserAssistEntries.push_back(std::move(e));
      }
    }
    std::stable_sort(out.registryUserAssistEntries.begin(), out.registryUserAssistEntries.end(),
                     [](const auto &a, const auto &b) { return a.decodedName.compare(b.decodedName, Qt::CaseInsensitive) < 0; });
    out.state = out.registryUserAssistEntries.empty() ? domain::ArtifactParseState::Partial : domain::ArtifactParseState::Parsed;
    out.summary = out.registryUserAssistEntries.empty() ? "UserAssist has no supported entries" : "UserAssist parsed";
    return out;
  }
};

class AmcacheProvider final : public IArtifactDetailProvider {
public:
  QString name() const override { return "windows.amcache"; }
  bool supports(const domain::ArtifactRecord &artifact) const override {
    return artifact.artifactName.compare("Amcache", Qt::CaseInsensitive) == 0 &&
           artifact.sourceLogicalPath.endsWith("Amcache.hve", Qt::CaseInsensitive);
  }
  domain::ArtifactDetails parse(const domain::ArtifactRecord &artifact,
                                const ArtifactDetailRequest &request) const override {
    domain::ArtifactDetails out;
    out.provider = name();
    QString error;
    const auto bytes = request.readBytes(artifact.sourceLogicalPath, error);
    if (!error.isEmpty()) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = error;
      out.summary = "Unable to read Amcache hive";
      return out;
    }
    RegistryHive hive;
    if (!hive.open(bytes, error)) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = error;
      out.summary = "Amcache parse failed";
      return out;
    }

    const QString appPath = "Root\\InventoryApplication";
    const auto apps = hive.childKeys(appPath, error);
    if (!error.isEmpty() || apps.empty()) {
      out.state = domain::ArtifactParseState::Unsupported;
      out.summary = "Amcache InventoryApplication key is not present";
      return out;
    }

    for (const auto &app : apps) {
      domain::ArtifactDetails::AmcacheEntry e;
      if (const auto *v = findValueCi(app, "LowerCaseLongPath")) e.programPath = decodeRegistryString(*v);
      if (const auto *v = findValueCi(app, "Name")) e.fileName = decodeRegistryString(*v);
      if (const auto *v = findValueCi(app, "FileId")) e.sha1 = decodeRegistryString(*v);
      if (const auto *v = findValueCi(app, "Publisher")) e.publisher = decodeRegistryString(*v);
      if (const auto *v = findValueCi(app, "ProductName")) e.productName = decodeRegistryString(*v);
      if (const auto *v = findValueCi(app, "Version")) e.version = decodeRegistryString(*v);
      if (const auto *v = findValueCi(app, "InstallDate")) e.installTimestamp = decodeFiletimeBlob(v->rawData);
      e.firstSeenTimestamp = app.lastWrite;
      if (e.fileName.isEmpty() && !e.programPath.isEmpty()) e.fileName = e.programPath.section('\\', -1);
      if (e.programPath.isEmpty() && e.fileName.isEmpty() && e.sha1.isEmpty() && e.publisher.isEmpty() &&
          e.productName.isEmpty() && e.version.isEmpty() && !e.firstSeenTimestamp.has_value() &&
          !e.installTimestamp.has_value()) {
        continue;
      }
      out.amcacheEntries.push_back(std::move(e));
    }

    std::stable_sort(out.amcacheEntries.begin(), out.amcacheEntries.end(), [](const auto &a, const auto &b) {
      if (a.firstSeenTimestamp.has_value() != b.firstSeenTimestamp.has_value()) return a.firstSeenTimestamp.has_value();
      if (a.firstSeenTimestamp && b.firstSeenTimestamp && a.firstSeenTimestamp.value() != b.firstSeenTimestamp.value()) {
        return a.firstSeenTimestamp.value() < b.firstSeenTimestamp.value();
      }
      return a.programPath.compare(b.programPath, Qt::CaseInsensitive) < 0;
    });
    out.state = out.amcacheEntries.empty() ? domain::ArtifactParseState::Partial : domain::ArtifactParseState::Parsed;
    out.summary = out.amcacheEntries.empty() ? "Amcache parsed with no conservative entries" : "Amcache parsed";
    return out;
  }
};

class BamDamProvider final : public IArtifactDetailProvider {
public:
  QString name() const override { return "windows.bam_dam"; }
  bool supports(const domain::ArtifactRecord &artifact) const override {
    return artifact.artifactName.compare("BAM/DAM resolver", Qt::CaseInsensitive) == 0 &&
           artifact.sourceLogicalPath.endsWith("/SYSTEM", Qt::CaseInsensitive);
  }
  domain::ArtifactDetails parse(const domain::ArtifactRecord &artifact,
                                const ArtifactDetailRequest &request) const override {
    domain::ArtifactDetails out;
    out.provider = name();
    QString error;
    const auto bytes = request.readBytes(artifact.sourceLogicalPath, error);
    if (!error.isEmpty()) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = error;
      out.summary = "Unable to read SYSTEM hive";
      return out;
    }
    RegistryHive hive;
    if (!hive.open(bytes, error)) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = error;
      out.summary = "BAM/DAM parse failed";
      return out;
    }

    const QString controlSet = resolveControlSetPathPrefix(hive, out.warnings);
    const auto collect = [&](const QString &source, const QString &basePath) {
      QString localError;
      const auto sidKeys = hive.childKeys(basePath, localError);
      if (!localError.isEmpty()) return;
      for (const auto &sidKey : sidKeys) {
        const QString sid = sidKey.path.section('\\', -1);
        for (const auto &value : sidKey.values) {
          if (value.name.compare("Version", Qt::CaseInsensitive) == 0) continue;
          domain::ArtifactDetails::BamDamEntry e;
          e.source = source;
          e.sid = sid;
          e.executablePath = value.name;
          e.lastExecutionTimestamp = decodeFiletimeBlob(value.rawData);
          out.bamDamEntries.push_back(std::move(e));
        }
      }
    };

    collect("bam", QString("%1\\Services\\bam\\State\\UserSettings").arg(controlSet));
    collect("dam", QString("%1\\Services\\dam\\State\\UserSettings").arg(controlSet));

    std::stable_sort(out.bamDamEntries.begin(), out.bamDamEntries.end(), [](const auto &a, const auto &b) {
      if (a.lastExecutionTimestamp.has_value() != b.lastExecutionTimestamp.has_value()) return a.lastExecutionTimestamp.has_value();
      if (a.lastExecutionTimestamp && b.lastExecutionTimestamp &&
          a.lastExecutionTimestamp.value() != b.lastExecutionTimestamp.value()) {
        return a.lastExecutionTimestamp.value() < b.lastExecutionTimestamp.value();
      }
      if (a.source.compare(b.source, Qt::CaseInsensitive) != 0) {
        return a.source.compare(b.source, Qt::CaseInsensitive) < 0;
      }
      return a.executablePath.compare(b.executablePath, Qt::CaseInsensitive) < 0;
    });

    out.state = out.bamDamEntries.empty() ? domain::ArtifactParseState::Unsupported
                                          : (out.warnings.isEmpty() ? domain::ArtifactParseState::Parsed
                                                                    : domain::ArtifactParseState::Partial);
    out.summary = out.bamDamEntries.empty() ? "BAM/DAM UserSettings keys are not present" : "BAM/DAM parsed";
    return out;
  }
};

class RecycleBinIProvider final : public IArtifactDetailProvider {
public:
  QString name() const override { return "windows.recycle_bin_i"; }

  bool supports(const domain::ArtifactRecord &artifact) const override {
    const auto base = artifact.sourceLogicalPath.section('/', -1);
    return base.startsWith("$I", Qt::CaseInsensitive);
  }

  domain::ArtifactDetails parse(const domain::ArtifactRecord &artifact,
                                const ArtifactDetailRequest &request) const override {
    domain::ArtifactDetails out;
    out.provider = name();
    QString error;
    const auto bytes = request.readBytes(artifact.sourceLogicalPath, error);
    if (!error.isEmpty()) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = error;
      out.summary = "Unable to read Recycle Bin $I payload";
      return out;
    }
    if (bytes.size() < 24) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = "Input too short for $I header";
      out.summary = "Recycle Bin $I parse failed";
      return out;
    }

    bool ok = false;
    const quint64 version = readLe64(bytes, 0, &ok);
    if (!ok) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = "Failed to parse version";
      out.summary = "Recycle Bin $I parse failed";
      return out;
    }

    out.originalSizeBytes = readLe64(bytes, 8);
    out.deletionTimestamp = filetimeToUtc(readLe64(bytes, 16));

    if (version != 1 && version != 2) {
      out.warnings.push_back(QString("Unknown $I version: %1").arg(version));
    }

    const QByteArray pathBytes = bytes.mid(24);
    if (pathBytes.isEmpty()) {
      out.state = domain::ArtifactParseState::Partial;
      out.summary = "Parsed $I header but original path is missing";
      out.warnings.push_back("Original path is absent");
      return out;
    }

    out.originalPath = decodeUtf16Le(pathBytes).trimmed();
    if (out.originalPath.isEmpty()) {
      out.state = domain::ArtifactParseState::Partial;
      out.summary = "Parsed $I header but original path is unavailable";
      out.warnings.push_back("Original path could not be decoded");
      return out;
    }

    out.state = out.warnings.isEmpty() ? domain::ArtifactParseState::Parsed : domain::ArtifactParseState::Partial;
    out.summary = "Recycle Bin $I parsed";
    return out;
  }
};

class LnkSummaryProvider final : public IArtifactDetailProvider {
public:
  QString name() const override { return "windows.lnk_summary"; }

  bool supports(const domain::ArtifactRecord &artifact) const override {
    return artifact.sourceLogicalPath.endsWith(".lnk", Qt::CaseInsensitive);
  }

  domain::ArtifactDetails parse(const domain::ArtifactRecord &artifact,
                                const ArtifactDetailRequest &request) const override {
    domain::ArtifactDetails out;
    out.provider = name();
    QString error;
    const auto bytes = request.readBytes(artifact.sourceLogicalPath, error);
    if (!error.isEmpty()) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = error;
      out.summary = "Unable to read .lnk payload";
      return out;
    }

    if (bytes.size() < static_cast<int>(kLnkHeaderSize)) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = "Input too short for Shell Link header";
      out.summary = ".lnk parse failed";
      return out;
    }

    const quint32 headerSize = readLe32(bytes, 0);
    if (headerSize != kLnkHeaderSize) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = "Unexpected Shell Link header size";
      out.summary = ".lnk parse failed";
      return out;
    }

    const quint32 flags = readLe32(bytes, 0x14);
    out.createdTimestamp = filetimeToUtc(readLe64(bytes, 0x1C));
    out.accessedTimestamp = filetimeToUtc(readLe64(bytes, 0x24));
    out.modifiedTimestamp = filetimeToUtc(readLe64(bytes, 0x2C));

    int cursor = static_cast<int>(kLnkHeaderSize);
    if ((flags & 0x00000001) != 0) {
      const quint16 idListSize = readLe16(bytes, cursor);
      cursor += 2 + idListSize;
      if (cursor > bytes.size()) {
        out.state = domain::ArtifactParseState::Partial;
        out.summary = "LNK IDList is truncated";
        out.warnings.push_back("IDList exceeds input length");
        return out;
      }
    }

    if ((flags & 0x00000002) != 0 && cursor + 4 <= bytes.size()) {
      const quint32 linkInfoSize = readLe32(bytes, cursor);
      if (linkInfoSize >= 0x1C && cursor + static_cast<int>(linkInfoSize) <= bytes.size()) {
        const int base = cursor;
        const quint32 headerSz = readLe32(bytes, base + 4);
        const quint32 localBaseOffset = readLe32(bytes, base + 16);
        const quint32 commonSuffixOffset = readLe32(bytes, base + 24);

        const QString localBase = localBaseOffset ? readNullTerminatedAnsi(bytes, base + static_cast<int>(localBaseOffset)) : QString();
        const QString suffix = commonSuffixOffset ? readNullTerminatedAnsi(bytes, base + static_cast<int>(commonSuffixOffset)) : QString();
        if (!localBase.isEmpty() && !suffix.isEmpty()) {
          out.targetPath = localBase + "\\" + suffix;
        } else if (!localBase.isEmpty()) {
          out.targetPath = localBase;
        }

        if (headerSz >= 0x24) {
          const quint32 localBaseOffsetUnicode = readLe32(bytes, base + 28);
          if (out.targetPath.isEmpty() && localBaseOffsetUnicode > 0) {
            const QByteArray unicodeBytes = bytes.mid(base + static_cast<int>(localBaseOffsetUnicode));
            out.targetPath = decodeUtf16Le(unicodeBytes);
          }
        }
      } else {
        out.warnings.push_back("LinkInfo section truncated");
      }
      cursor += static_cast<int>(linkInfoSize);
    }

    auto readStringData = [&](QString &dest) {
      if (cursor + 2 > bytes.size()) {
        out.warnings.push_back("StringData header truncated");
        return false;
      }
      const quint16 count = readLe16(bytes, cursor);
      cursor += 2;
      const bool unicode = (flags & 0x00000080) != 0;
      const int byteCount = unicode ? count * 2 : count;
      if (cursor + byteCount > bytes.size()) {
        out.warnings.push_back("StringData field truncated");
        return false;
      }
      const QByteArray valueBytes = bytes.mid(cursor, byteCount);
      dest = unicode ? decodeUtf16Le(valueBytes) : QString::fromLatin1(valueBytes);
      cursor += byteCount;
      return true;
    };

    if ((flags & 0x00000008) != 0) {
      QString ignored;
      readStringData(ignored);
    }
    if ((flags & 0x00000010) != 0) {
      readStringData(out.relativePath);
    }
    if ((flags & 0x00000020) != 0) {
      readStringData(out.workingDirectory);
    }
    if ((flags & 0x00000040) != 0) {
      readStringData(out.commandLineArguments);
    }

    const bool anyField = !out.targetPath.isEmpty() || !out.relativePath.isEmpty() || !out.workingDirectory.isEmpty() ||
                          !out.commandLineArguments.isEmpty() || out.createdTimestamp.has_value() ||
                          out.modifiedTimestamp.has_value() || out.accessedTimestamp.has_value();
    out.state = !anyField ? domain::ArtifactParseState::Partial
                          : (out.warnings.isEmpty() ? domain::ArtifactParseState::Parsed
                                                    : domain::ArtifactParseState::Partial);
    out.summary = anyField ? "Shell Link summary parsed" : "Shell Link parsed with limited fields";
    if (!anyField) out.warnings.push_back("No conservative summary fields were available");
    return out;
  }
};

class PrefetchSummaryProvider final : public IArtifactDetailProvider {
public:
  QString name() const override { return "windows.prefetch_summary"; }

  bool supports(const domain::ArtifactRecord &artifact) const override {
    return artifact.sourceLogicalPath.endsWith(".pf", Qt::CaseInsensitive);
  }

  domain::ArtifactDetails parse(const domain::ArtifactRecord &artifact,
                                const ArtifactDetailRequest &request) const override {
    domain::ArtifactDetails out;
    out.provider = name();

    QString error;
    const auto bytes = request.readBytes(artifact.sourceLogicalPath, error);
    if (!error.isEmpty()) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = error;
      out.summary = "Unable to read Prefetch payload";
      return out;
    }
    if (bytes.size() < 0x90) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = "Input too short for Prefetch header";
      out.summary = "Prefetch parse failed";
      return out;
    }

    const quint32 version = readLe32(bytes, 0);
    out.formatVersion = static_cast<int>(version);
    if (bytes.mid(4, 4) != QByteArray("SCCA", 4)) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = "Missing Prefetch SCCA signature";
      out.summary = "Prefetch parse failed";
      return out;
    }

    out.executableName = decodeUtf16Le(bytes.mid(16, 60)).trimmed();

    auto appendRunTimes = [&](int off, int count) {
      for (int i = 0; i < count; ++i) {
        bool ok = false;
        const quint64 ft = readLe64(bytes, off + (i * 8), &ok);
        if (!ok) {
          out.warnings.push_back("Last-run timestamp field is truncated");
          break;
        }
        const auto dt = filetimeToUtc(ft);
        if (dt) out.lastRunTimestamps.push_back(*dt);
      }
    };

    switch (version) {
    case 17:
      out.runCount = readLe32(bytes, 0x90);
      appendRunTimes(0x78, 1);
      break;
    case 23:
      out.runCount = readLe32(bytes, 0x98);
      appendRunTimes(0x80, 1);
      break;
    case 26:
    case 30:
      out.runCount = readLe32(bytes, 0xD0);
      appendRunTimes(0x80, 8);
      break;
    default:
      out.warnings.push_back(QString("Unsupported Prefetch version: %1").arg(version));
      appendRunTimes(0x80, 8);
      break;
    }

    const bool useful = !out.executableName.isEmpty() || out.runCount.has_value() || !out.lastRunTimestamps.empty();
    out.state = useful ? (out.warnings.isEmpty() ? domain::ArtifactParseState::Parsed : domain::ArtifactParseState::Partial)
                       : domain::ArtifactParseState::Partial;
    out.summary = useful ? "Prefetch summary parsed" : "Prefetch parsed with limited fields";
    if (!useful) out.warnings.push_back("No conservative Prefetch fields were available");
    return out;
  }
};

class ChromiumHistoryProvider final : public IArtifactDetailProvider {
public:
  QString name() const override { return "windows.chromium_history"; }

  bool supports(const domain::ArtifactRecord &artifact) const override {
    if (!artifact.sourceLogicalPath.endsWith("/History", Qt::CaseInsensitive)) return false;
    return artifact.artifactName.compare("Chrome History", Qt::CaseInsensitive) == 0 ||
           artifact.artifactName.compare("Edge History", Qt::CaseInsensitive) == 0;
  }

  domain::ArtifactDetails parse(const domain::ArtifactRecord &artifact,
                                const ArtifactDetailRequest &request) const override {
    domain::ArtifactDetails out;
    out.provider = name();
#if !defined(FIE_HAS_SQLITE)
    Q_UNUSED(artifact)
    Q_UNUSED(request)
    out.state = domain::ArtifactParseState::Unsupported;
    out.summary = "SQLite support is unavailable in this build";
    return out;
#else
    QString materializeError;
    auto materialized = materializeArtifactReadOnly(artifact.sourceLogicalPath, request.readBytes, materializeError);
    if (!materializeError.isEmpty() || !materialized.valid()) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = materializeError.isEmpty() ? "Failed to materialize History database" : materializeError;
      out.summary = "Chromium History parse failed";
      return out;
    }

    sqlite3 *db = nullptr;
    if (sqlite3_open_v2(materialized.localPath().toUtf8().constData(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = db ? QString::fromUtf8(sqlite3_errmsg(db)) : "sqlite open failed";
      out.summary = "Chromium History parse failed";
      if (db) sqlite3_close(db);
      return out;
    }

    auto chromiumTsToUtc = [](sqlite3_int64 micros) -> std::optional<QDateTime> {
      if (micros <= 0) return std::nullopt;
      constexpr qint64 kChromiumUnixEpochOffsetMicros = 11644473600000000LL;
      const qint64 unixMicros = static_cast<qint64>(micros) - kChromiumUnixEpochOffsetMicros;
      if (unixMicros <= 0) return std::nullopt;
      return QDateTime::fromMSecsSinceEpoch(unixMicros / 1000, Qt::UTC);
    };

    const char *visitSql =
        "SELECT urls.url, urls.title, visits.visit_time, urls.visit_count "
        "FROM visits JOIN urls ON visits.url = urls.id "
        "ORDER BY visits.visit_time DESC LIMIT 200;";
    sqlite3_stmt *visitStmt = nullptr;
    if (sqlite3_prepare_v2(db, visitSql, -1, &visitStmt, nullptr) == SQLITE_OK) {
      while (sqlite3_step(visitStmt) == SQLITE_ROW) {
        domain::ArtifactDetails::BrowserVisit visit;
        visit.url = QString::fromUtf8(reinterpret_cast<const char *>(sqlite3_column_text(visitStmt, 0)));
        visit.title = QString::fromUtf8(reinterpret_cast<const char *>(sqlite3_column_text(visitStmt, 1)));
        visit.timestamp = chromiumTsToUtc(sqlite3_column_int64(visitStmt, 2));
        const int vc = sqlite3_column_int(visitStmt, 3);
        if (vc > 0) visit.visitCount = static_cast<quint32>(vc);
        out.browserVisits.push_back(std::move(visit));
      }
    } else {
      out.warnings.push_back("History visits query unavailable");
    }
    if (visitStmt) sqlite3_finalize(visitStmt);

    const char *downloadSql =
        "SELECT tab_url, target_path, start_time "
        "FROM downloads ORDER BY start_time DESC LIMIT 200;";
    sqlite3_stmt *downloadStmt = nullptr;
    if (sqlite3_prepare_v2(db, downloadSql, -1, &downloadStmt, nullptr) == SQLITE_OK) {
      while (sqlite3_step(downloadStmt) == SQLITE_ROW) {
        domain::ArtifactDetails::BrowserDownload dl;
        dl.url = QString::fromUtf8(reinterpret_cast<const char *>(sqlite3_column_text(downloadStmt, 0)));
        dl.targetPath = QString::fromUtf8(reinterpret_cast<const char *>(sqlite3_column_text(downloadStmt, 1)));
        dl.timestamp = chromiumTsToUtc(sqlite3_column_int64(downloadStmt, 2));
        out.browserDownloads.push_back(std::move(dl));
      }
    } else {
      out.warnings.push_back("History downloads query unavailable");
    }
    if (downloadStmt) sqlite3_finalize(downloadStmt);
    sqlite3_close(db);

    const bool hasData = !out.browserVisits.empty() || !out.browserDownloads.empty();
    out.state = hasData ? (out.warnings.isEmpty() ? domain::ArtifactParseState::Parsed : domain::ArtifactParseState::Partial)
                        : domain::ArtifactParseState::Partial;
    out.summary = hasData ? "Chromium History parsed" : "Chromium History parsed with no rows";
    if (!hasData) out.warnings.push_back("No visit/download rows available");
    return out;
#endif
  }
};

} // namespace

ArtifactDetailService::ArtifactDetailService()
    : ArtifactDetailService([] {
        std::vector<std::unique_ptr<IArtifactDetailProvider>> providers;
        providers.push_back(std::make_unique<RecycleBinIProvider>());
        providers.push_back(std::make_unique<LnkSummaryProvider>());
        providers.push_back(std::make_unique<PrefetchSummaryProvider>());
        providers.push_back(std::make_unique<RegistryRunMruProvider>());
        providers.push_back(std::make_unique<RegistryRecentDocsProvider>());
        providers.push_back(std::make_unique<RegistryUserAssistProvider>());
        providers.push_back(std::make_unique<AmcacheProvider>());
        providers.push_back(std::make_unique<BamDamProvider>());
        providers.push_back(std::make_unique<ChromiumHistoryProvider>());
        return providers;
      }()) {}

ArtifactDetailService::ArtifactDetailService(std::vector<std::unique_ptr<IArtifactDetailProvider>> providers)
    : m_providers(std::move(providers)) {}

std::optional<domain::ArtifactDetails> ArtifactDetailService::describe(const domain::ArtifactRecord &artifact,
                                                                       const ArtifactDetailRequest &request) const {
  for (const auto &provider : m_providers) {
    if (!provider->supports(artifact)) continue;
    return provider->parse(artifact, request);
  }
  return std::nullopt;
}

void ArtifactDetailService::populate(std::vector<domain::ArtifactRecord> &artifacts,
                                     const ArtifactDetailRequest &request,
                                     QStringList &warnings) const {
  for (auto &artifact : artifacts) {
    if (artifact.status.compare("Present", Qt::CaseInsensitive) != 0 || artifact.directoryTarget) {
      artifact.details = std::nullopt;
      continue;
    }
    artifact.details = describe(artifact, request);
    if (!artifact.details.has_value()) continue;
    if (artifact.details->state == domain::ArtifactParseState::Failed) {
      warnings.push_back(QString("Artifact detail parse failed for %1: %2")
                             .arg(artifact.sourceLogicalPath,
                                  artifact.details->error.isEmpty() ? artifact.details->summary : artifact.details->error));
    }
  }
}

} // namespace fie::forensics
