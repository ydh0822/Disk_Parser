#include "ForensicImageExtractor/forensics/ArtifactDetailProviders.h"
#include "ForensicImageExtractor/forensics/ArtifactTimelineService.h"
#include "ForensicImageExtractor/forensics/RegistryHive.h"
#include "ForensicImageExtractor/cli/ArtifactJson.h"

namespace {

QByteArray le16(quint16 v) {
  QByteArray b(2, 0);
  b[0] = static_cast<char>(v & 0xFF);
  b[1] = static_cast<char>((v >> 8) & 0xFF);
  return b;
}
QByteArray le32(quint32 v) {
  QByteArray b(4, 0);
  b[0] = static_cast<char>(v & 0xFF);
  b[1] = static_cast<char>((v >> 8) & 0xFF);
  b[2] = static_cast<char>((v >> 16) & 0xFF);
  b[3] = static_cast<char>((v >> 24) & 0xFF);
  return b;
}
QByteArray le64(quint64 v) {
  QByteArray b(8, 0);
  for (int i = 0; i < 8; ++i) b[i] = static_cast<char>((v >> (8 * i)) & 0xFF);
  return b;
}
QByteArray utf16z(const QString &s) {
  QByteArray out(reinterpret_cast<const char *>(s.utf16()), s.size() * 2);
  out += QByteArray("\0\0", 2);
  return out;
}

struct HiveBuilder {
  QByteArray h;
  int cursor{0x1020};

  HiveBuilder() {
    h = QByteArray(0x5000, 0);
    h.replace(0, 4, QByteArray("regf", 4));
    h.replace(0x1000, 4, QByteArray("hbin", 4));
    h.replace(0x1008, 4, le32(0x4000));
  }

  quint32 addCell(const QByteArray &body) {
    const int size = 4 + body.size();
    const int padded = (size + 7) & ~7;
    const qint32 neg = -padded;
    h.replace(cursor, 4, le32(static_cast<quint32>(neg)));
    h.replace(cursor + 4, body.size(), body);
    const quint32 rel = static_cast<quint32>(cursor - 0x1000);
    cursor += padded;
    return rel;
  }

  quint32 addDataCell(const QByteArray &data) { return addCell(data); }

  quint32 addValue(const QString &name, quint32 type, const QByteArray &raw) {
    const quint32 dataRel = addDataCell(raw);
    QByteArray body(0x14, 0);
    body.replace(0, 2, QByteArray("vk", 2));
    body.replace(0x2, 2, le16(static_cast<quint16>(name.toLatin1().size())));
    body.replace(0x4, 4, le32(static_cast<quint32>(raw.size())));
    body.replace(0x8, 4, le32(dataRel));
    body.replace(0xC, 4, le32(type));
    body += name.toLatin1();
    return addCell(body);
  }

  quint32 addValueList(const std::vector<quint32> &values) {
    QByteArray body;
    for (auto v : values) body += le32(v);
    return addCell(body);
  }

  quint32 addSubkeyList(const std::vector<quint32> &subkeys) {
    QByteArray body;
    body += QByteArray("li", 2);
    body += le16(static_cast<quint16>(subkeys.size()));
    for (auto s : subkeys) body += le32(s);
    return addCell(body);
  }

  quint32 addKey(const QString &name,
                 const std::vector<quint32> &subkeys,
                 const std::vector<quint32> &values,
                 quint64 ft = 132537600000000000ULL) {
    const quint32 subList = subkeys.empty() ? 0xFFFFFFFF : addSubkeyList(subkeys);
    const quint32 valList = values.empty() ? 0xFFFFFFFF : addValueList(values);
    QByteArray body(0x4C, 0);
    body.replace(0, 2, QByteArray("nk", 2));
    body.replace(0x8, 8, le64(ft));
    body.replace(0x14, 4, le32(static_cast<quint32>(subkeys.size())));
    body.replace(0x1C, 4, le32(subList));
    body.replace(0x24, 4, le32(static_cast<quint32>(values.size())));
    body.replace(0x28, 4, le32(valList));
    body.replace(0x48, 2, le16(static_cast<quint16>(name.toLatin1().size())));
    body += name.toLatin1();
    return addCell(body);
  }
};

QByteArray buildSyntheticNtUserHive() {
  HiveBuilder b;

  const auto runA = b.addValue("a", 1, utf16z("cmd.exe"));
  const auto runB = b.addValue("b", 1, utf16z("notepad.exe"));
  const auto runMru = b.addValue("MRUList", 1, QByteArray("ba"));
  const auto runMruKey = b.addKey("RunMRU", {}, {runA, runB, runMru});

  const auto tp1 = b.addValue("url1", 1, utf16z("C:\\Windows"));
  const auto typedPaths = b.addKey("TypedPaths", {}, {tp1}, 116444736000000000ULL);

  const auto rd0 = b.addValue("0", 1, utf16z("alpha.txt"));
  QByteArray mruEx;
  mruEx += le32(0);
  mruEx += le32(0xFFFFFFFF);
  const auto rdMru = b.addValue("MRUListEx", 3, mruEx);
  const auto recentAll = b.addKey("RecentDocs", {}, {rd0, rdMru});

  const auto uaName = b.addValue("P:\\Jvaqbjf\\flfgrz32\\pzq.rkr", 3,
                                 QByteArray(72, 0).replace(4, 4, le32(5)).replace(60, 8, le64(132537700000000000ULL)));
  const auto uaCount = b.addKey("Count", {}, {uaName});
  const auto uaGuid = b.addKey("{FAKE-GUID}", {uaCount}, {});
  const auto userAssist = b.addKey("UserAssist", {uaGuid}, {});

  const auto explorer = b.addKey("Explorer", {runMruKey, typedPaths, recentAll, userAssist}, {});
  const auto cv = b.addKey("CurrentVersion", {explorer}, {});
  const auto win = b.addKey("Windows", {cv}, {});
  const auto ms = b.addKey("Microsoft", {win}, {});
  const auto software = b.addKey("Software", {ms}, {});
  const auto root = b.addKey("ROOT", {software}, {});

  b.h.replace(0x24, 4, le32(root));
  return b.h;
}

} // namespace

int runRegistryRecentActivityTests() {
  const QByteArray hiveBytes = buildSyntheticNtUserHive();

  // focused REGF helper checks
  fie::forensics::RegistryHive hive;
  QString error;
  if (!hive.open(hiveBytes, error)) return 1;
  const auto runMru = hive.keyByPath("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", error);
  if (!runMru.has_value()) return 1;
  const auto typedPathsKey = hive.keyByPath("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", error);
  if (!typedPathsKey.has_value()) return 1;
  if (!typedPathsKey->lastWrite.has_value()) return 1;
  if (typedPathsKey->lastWrite->toSecsSinceEpoch() != 0) return 1;

  fie::forensics::ArtifactDetailService service;

  fie::domain::ArtifactRecord run;
  run.artifactName = "Run/RunOnce resolver";
  run.sourceLogicalPath = "/Users/Alice/NTUSER.DAT";
  const auto runDetails = service.describe(run, {[&](const QString &, QString &) { return hiveBytes; }});
  if (!runDetails.has_value() || runDetails->provider != "windows.registry_run_mru") return 1;
  if (runDetails->registryRunMruEntries.size() != 2) return 1;
  if (!runDetails->registryRunMruEntries.front().mruPosition.has_value()) return 1;

  fie::domain::ArtifactRecord recent;
  recent.artifactName = "RecentDocs resolver";
  recent.sourceLogicalPath = "/Users/Alice/NTUSER.DAT";
  const auto recentDetails = service.describe(recent, {[&](const QString &, QString &) { return hiveBytes; }});
  if (!recentDetails.has_value() || recentDetails->provider != "windows.registry_recent_docs") return 1;
  if (recentDetails->registryTypedPathEntries.empty()) return 1;
  if (recentDetails->registryRecentDocEntries.empty()) return 1;

  fie::domain::ArtifactRecord typedOnly;
  typedOnly.artifactName = "TypedPaths resolver";
  typedOnly.sourceLogicalPath = "/Users/Alice/NTUSER.DAT";
  if (service.describe(typedOnly, {[&](const QString &, QString &) { return hiveBytes; }}).has_value()) return 1;

  fie::domain::ArtifactRecord ua;
  ua.artifactName = "UserAssist resolver";
  ua.sourceLogicalPath = "/Users/Alice/NTUSER.DAT";
  const auto uaDetails = service.describe(ua, {[&](const QString &, QString &) { return hiveBytes; }});
  if (!uaDetails.has_value() || uaDetails->provider != "windows.registry_userassist") return 1;
  if (uaDetails->registryUserAssistEntries.empty()) return 1;
  if (!uaDetails->registryUserAssistEntries.front().runCount.has_value()) return 1;

  // timeline normalization
  run.details = runDetails;
  run.category = "Execution";
  recent.details = recentDetails;
  recent.category = "Execution";
  ua.details = uaDetails;
  ua.category = "Execution";
  std::vector<fie::domain::ArtifactRecord> artifacts{run, recent, ua};
  fie::forensics::ArtifactTimelineService timelineSvc;
  const auto events = timelineSvc.buildEvents(artifacts);
  bool sawRun = false;
  bool sawTyped = false;
  bool sawRecent = false;
  bool sawUa = false;
  for (const auto &e : events) {
    sawRun = sawRun || e.eventType == "registry_run_mru";
    sawTyped = sawTyped || e.eventType == "registry_typed_path";
    sawRecent = sawRecent || e.eventType == "registry_recent_doc";
    sawUa = sawUa || e.eventType == "userassist_execution";
  }
  if (!sawRun || !sawTyped || !sawRecent || !sawUa) return 1;

  // JSON null handling and arrays
  auto json = fie::cli::artifactDetailsToJson(*recentDetails);
  if (!json.contains("registry_typed_path_entries") || json.value("registry_typed_path_entries").toArray().isEmpty()) return 1;
  if (!json.contains("registry_userassist_entries") || !json.value("registry_userassist_entries").toArray().isEmpty()) return 1;

  // unsupported / failed behavior
  QByteArray bad("nope");
  const auto failed = service.describe(run, {[&](const QString &, QString &) { return bad; }});
  if (!failed.has_value() || failed->state != fie::domain::ArtifactParseState::Failed) return 1;

  return 0;
}
