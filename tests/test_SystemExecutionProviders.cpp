#include "ForensicImageExtractor/forensics/ArtifactDetailProviders.h"
#include "ForensicImageExtractor/forensics/ArtifactTimelineService.h"
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
  quint32 addValue(const QString &name, quint32 type, const QByteArray &raw) {
    const auto dataRel = addCell(raw);
    QByteArray vk(0x14, 0);
    vk.replace(0, 2, QByteArray("vk", 2));
    vk.replace(0x2, 2, le16(static_cast<quint16>(name.toLatin1().size())));
    vk.replace(0x4, 4, le32(static_cast<quint32>(raw.size())));
    vk.replace(0x8, 4, le32(dataRel));
    vk.replace(0xC, 4, le32(type));
    vk += name.toLatin1();
    return addCell(vk);
  }
  quint32 addValueList(const std::vector<quint32> &values) {
    QByteArray b;
    for (auto v : values) b += le32(v);
    return addCell(b);
  }
  quint32 addSubkeyList(const std::vector<quint32> &subkeys) {
    QByteArray b;
    b += QByteArray("li", 2);
    b += le16(static_cast<quint16>(subkeys.size()));
    for (auto s : subkeys) b += le32(s);
    return addCell(b);
  }
  quint32 addKey(const QString &name, const std::vector<quint32> &subkeys, const std::vector<quint32> &values,
                 quint64 ft = 132537600000000000ULL) {
    const auto subList = subkeys.empty() ? 0xFFFFFFFF : addSubkeyList(subkeys);
    const auto valList = values.empty() ? 0xFFFFFFFF : addValueList(values);
    QByteArray nk(0x4C, 0);
    nk.replace(0, 2, QByteArray("nk", 2));
    nk.replace(0x8, 8, le64(ft));
    nk.replace(0x14, 4, le32(static_cast<quint32>(subkeys.size())));
    nk.replace(0x1C, 4, le32(subList));
    nk.replace(0x24, 4, le32(static_cast<quint32>(values.size())));
    nk.replace(0x28, 4, le32(valList));
    nk.replace(0x48, 2, le16(static_cast<quint16>(name.toLatin1().size())));
    nk += name.toLatin1();
    return addCell(nk);
  }
};

QByteArray buildAmcacheHive() {
  HiveBuilder b;
  const auto path = b.addValue("LowerCaseLongPath", 1, utf16z("c:\\program files\\app\\app.exe"));
  const auto name = b.addValue("Name", 1, utf16z("app.exe"));
  const auto sha1 = b.addValue("FileId", 1, utf16z("0000ABCDEF"));
  const auto publisher = b.addValue("Publisher", 1, utf16z("ACME"));
  const auto product = b.addValue("ProductName", 1, utf16z("Acme App"));
  const auto version = b.addValue("Version", 1, utf16z("1.2.3"));
  const auto install = b.addValue("InstallDate", 3, le64(132537700000000000ULL));
  const auto item = b.addKey("{APP-1}", {}, {path, name, sha1, publisher, product, version, install}, 132537800000000000ULL);

  const auto invApp = b.addKey("InventoryApplication", {item}, {});
  const auto root = b.addKey("Root", {invApp}, {});
  const auto hiveRoot = b.addKey("ROOT", {root}, {});
  b.h.replace(0x24, 4, le32(hiveRoot));
  return b.h;
}

QByteArray buildSystemHiveForBamDam() {
  HiveBuilder b;
  const auto bamExec = b.addValue("\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe", 3, le64(132537710000000000ULL));
  const auto bamSid = b.addKey("S-1-5-21-1001", {}, {bamExec});
  const auto bamUsers = b.addKey("UserSettings", {bamSid}, {});
  const auto bamState = b.addKey("State", {bamUsers}, {});
  const auto bamSvc = b.addKey("bam", {bamState}, {});

  const auto damExec = b.addValue("\\Device\\HarddiskVolume3\\Windows\\System32\\notepad.exe", 3, le64(132537720000000000ULL));
  const auto damSid = b.addKey("S-1-5-21-1002", {}, {damExec});
  const auto damUsers = b.addKey("UserSettings", {damSid}, {});
  const auto damState = b.addKey("State", {damUsers}, {});
  const auto damSvc = b.addKey("dam", {damState}, {});

  const auto services = b.addKey("Services", {bamSvc, damSvc}, {});
  const auto cs2 = b.addKey("ControlSet002", {services}, {});
  const auto currentVal = b.addValue("Current", 4, le32(2));
  const auto select = b.addKey("Select", {}, {currentVal});
  const auto hiveRoot = b.addKey("ROOT", {cs2, select}, {});
  b.h.replace(0x24, 4, le32(hiveRoot));
  return b.h;
}

QByteArray buildSystemHiveWithoutSelect() {
  HiveBuilder b;
  const auto bamExec = b.addValue("\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe", 3, le64(132537710000000000ULL));
  const auto bamSid = b.addKey("S-1-5-21-1001", {}, {bamExec});
  const auto bamUsers = b.addKey("UserSettings", {bamSid}, {});
  const auto bamState = b.addKey("State", {bamUsers}, {});
  const auto bamSvc = b.addKey("bam", {bamState}, {});
  const auto services = b.addKey("Services", {bamSvc}, {});
  const auto cs1 = b.addKey("ControlSet001", {services}, {});
  const auto hiveRoot = b.addKey("ROOT", {cs1}, {});
  b.h.replace(0x24, 4, le32(hiveRoot));
  return b.h;
}

} // namespace

int runSystemExecutionProviderTests() {
  fie::forensics::ArtifactDetailService service;

  fie::domain::ArtifactRecord amcache;
  amcache.artifactName = "Amcache";
  amcache.sourceLogicalPath = "/Windows/AppCompat/Programs/Amcache.hve";
  const auto amcacheHive = buildAmcacheHive();
  const auto amcacheDetails = service.describe(amcache, {[&](const QString &, QString &) { return amcacheHive; }});
  if (!amcacheDetails.has_value() || amcacheDetails->provider != "windows.amcache") return 1;
  if (amcacheDetails->amcacheEntries.empty()) return 1;
  if (!amcacheDetails->amcacheEntries.front().firstSeenTimestamp.has_value()) return 1;

  fie::domain::ArtifactRecord system;
  system.artifactName = "BAM/DAM resolver";
  system.sourceLogicalPath = "/Windows/System32/config/SYSTEM";
  const auto systemHive = buildSystemHiveForBamDam();
  const auto bamDamDetails = service.describe(system, {[&](const QString &, QString &) { return systemHive; }});
  if (!bamDamDetails.has_value() || bamDamDetails->provider != "windows.bam_dam") return 1;
  if (bamDamDetails->bamDamEntries.size() < 2) return 1;
  if (bamDamDetails->state != fie::domain::ArtifactParseState::Parsed) return 1;

  const auto unsupported = service.describe(system, {[&](const QString &, QString &) { return amcacheHive; }});
  if (!unsupported.has_value() || unsupported->state != fie::domain::ArtifactParseState::Unsupported) return 1;

  const auto noSelectHive = buildSystemHiveWithoutSelect();
  const auto noSelect = service.describe(system, {[&](const QString &, QString &) { return noSelectHive; }});
  if (!noSelect.has_value() || noSelect->state != fie::domain::ArtifactParseState::Partial) return 1;
  if (noSelect->warnings.isEmpty()) return 1;

  amcache.details = amcacheDetails;
  system.details = bamDamDetails;
  std::vector<fie::domain::ArtifactRecord> records{amcache, system};

  fie::forensics::ArtifactTimelineService timeline;
  const auto events = timeline.buildEvents(records);
  bool sawAmcache = false;
  bool sawBam = false;
  bool sawDam = false;
  for (const auto &e : events) {
    sawAmcache = sawAmcache || e.eventType == "amcache_entry";
    sawBam = sawBam || e.eventType == "bam_execution";
    sawDam = sawDam || e.eventType == "dam_execution";
  }
  if (!sawAmcache || !sawBam || !sawDam) return 1;

  const auto amcacheJson = fie::cli::artifactDetailsToJson(*amcacheDetails);
  if (!amcacheJson.contains("amcache_entries") || amcacheJson.value("amcache_entries").toArray().isEmpty()) return 1;
  if (!amcacheJson.contains("bam_dam_entries") || !amcacheJson.value("bam_dam_entries").toArray().isEmpty()) return 1;

  QByteArray bad("invalid-hive");
  const auto failed = service.describe(system, {[&](const QString &, QString &) { return bad; }});
  if (!failed.has_value() || failed->state != fie::domain::ArtifactParseState::Failed) return 1;

  return 0;
}
