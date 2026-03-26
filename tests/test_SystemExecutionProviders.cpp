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

  QByteArray appCompatRaw;
  appCompatRaw += utf16z("C:\\Windows\\System32\\calc.exe");
  appCompatRaw += utf16z("\\Device\\HarddiskVolume3\\Program Files\\App\\app.exe");
  const auto appCompatValue = b.addValue("AppCompatCache", 3, appCompatRaw);
  const auto appCompatKey = b.addKey("AppCompatCache", {}, {appCompatValue});
  const auto sessionMgr = b.addKey("Session Manager", {appCompatKey}, {});
  const auto control = b.addKey("Control", {sessionMgr}, {});

  const auto disp = b.addValue("DisplayName", 1, utf16z("Acme Service"));
  const auto image = b.addValue("ImagePath", 1, utf16z("C:\\Program Files\\Acme\\svc.exe"));
  const auto obj = b.addValue("ObjectName", 1, utf16z("LocalSystem"));
  const auto desc = b.addValue("Description", 1, utf16z("Synthetic service"));
  const auto start = b.addValue("Start", 4, le32(2));
  const auto type = b.addValue("Type", 4, le32(0x10));
  const auto delayed = b.addValue("DelayedAutostart", 4, le32(1));
  QByteArray depSvc = utf16z("Tcpip");
  depSvc += QByteArray("\0\0", 2);
  const auto dependSvc = b.addValue("DependOnService", 7, depSvc);
  const auto dll = b.addValue("ServiceDll", 1, utf16z("C:\\Program Files\\Acme\\svc.dll"));
  const auto params = b.addKey("Parameters", {}, {dll});
  const auto mySvc = b.addKey("AcmeSvc", {params}, {disp, image, obj, desc, start, type, delayed, dependSvc});

  const auto servicesWithSvc = b.addKey("Services", {bamSvc, damSvc, mySvc}, {});
  const auto cs2 = b.addKey("ControlSet002", {servicesWithSvc, control}, {});
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

QByteArray buildSystemHiveWithTruncatedAppCompat() {
  HiveBuilder b;
  QByteArray appCompatRaw;
  appCompatRaw += utf16z("C:\\Windows\\System32\\notepad.exe");
  appCompatRaw += QByteArray(1, '\x41'); // odd trailing byte
  const auto appCompatValue = b.addValue("AppCompatCache", 3, appCompatRaw);
  const auto appCompatKey = b.addKey("AppCompatCache", {}, {appCompatValue});
  const auto sessionMgr = b.addKey("Session Manager", {appCompatKey}, {});
  const auto control = b.addKey("Control", {sessionMgr}, {});
  const auto cs1 = b.addKey("ControlSet001", {control}, {});
  const auto currentVal = b.addValue("Current", 4, le32(1));
  const auto select = b.addKey("Select", {}, {currentVal});
  const auto hiveRoot = b.addKey("ROOT", {cs1, select}, {});
  b.h.replace(0x24, 4, le32(hiveRoot));
  return b.h;
}

QByteArray buildSystemHiveWithUnsupportedAppCompatPayload() {
  HiveBuilder b;
  QByteArray appCompatRaw("\x01\x02\x03\x04\x05\x06", 6);
  const auto appCompatValue = b.addValue("AppCompatCache", 3, appCompatRaw);
  const auto appCompatKey = b.addKey("AppCompatCache", {}, {appCompatValue});
  const auto sessionMgr = b.addKey("Session Manager", {appCompatKey}, {});
  const auto control = b.addKey("Control", {sessionMgr}, {});
  const auto cs1 = b.addKey("ControlSet001", {control}, {});
  const auto currentVal = b.addValue("Current", 4, le32(1));
  const auto select = b.addKey("Select", {}, {currentVal});
  const auto hiveRoot = b.addKey("ROOT", {cs1, select}, {});
  b.h.replace(0x24, 4, le32(hiveRoot));
  return b.h;
}

QByteArray buildSystemHiveForUsbStor() {
  HiveBuilder b;
  const auto friendly = b.addValue("FriendlyName", 1, utf16z("SanDisk Cruzer USB Device"));
  const auto parent = b.addValue("ParentIdPrefix", 1, utf16z("7&1111111&0"));
  const auto service = b.addValue("Service", 1, utf16z("USBSTOR"));
  const auto cls = b.addValue("ClassGUID", 1, utf16z("{36fc9e60-c465-11cf-8056-444553540000}"));
  const auto instance =
      b.addKey("123ABC&0", {}, {friendly, parent, service, cls}, 132537730000000000ULL);
  const auto dev = b.addKey("Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00", {instance}, {});
  const auto usbstor = b.addKey("USBSTOR", {dev}, {});
  const auto enumKey = b.addKey("Enum", {usbstor}, {});
  const auto cs2 = b.addKey("ControlSet002", {enumKey}, {});
  const auto currentVal = b.addValue("Current", 4, le32(2));
  const auto select = b.addKey("Select", {}, {currentVal});
  const auto hiveRoot = b.addKey("ROOT", {cs2, select}, {});
  b.h.replace(0x24, 4, le32(hiveRoot));
  return b.h;
}

QByteArray buildSystemHiveWithoutUsbStor() {
  HiveBuilder b;
  const auto enumKey = b.addKey("Enum", {}, {});
  const auto cs1 = b.addKey("ControlSet001", {enumKey}, {});
  const auto currentVal = b.addValue("Current", 4, le32(1));
  const auto select = b.addKey("Select", {}, {currentVal});
  const auto hiveRoot = b.addKey("ROOT", {cs1, select}, {});
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

  fie::domain::ArtifactRecord appCompat;
  appCompat.artifactName = "AppCompatCache resolver";
  appCompat.sourceLogicalPath = "/Windows/System32/config/SYSTEM";
  const auto appCompatDetails = service.describe(appCompat, {[&](const QString &, QString &) { return systemHive; }});
  if (!appCompatDetails.has_value() || appCompatDetails->provider != "windows.appcompatcache_v1") return 1;
  if (appCompatDetails->appCompatCacheEntries.empty()) return 1;
  if (!appCompatDetails->appCompatCacheEntries.front().entryIndex.has_value()) return 1;
  if (appCompatDetails->appCompatCacheEntries.front().lastModifiedTimestamp.has_value()) return 1;
  if (appCompatDetails->appCompatCacheEntries.front().executionFlag.has_value()) return 1;
  const auto appCompatJson = fie::cli::artifactDetailsToJson(*appCompatDetails);
  if (!appCompatJson.contains("appcompatcache_entries") || appCompatJson.value("appcompatcache_entries").toArray().isEmpty()) return 1;

  fie::domain::ArtifactRecord servicesRec;
  servicesRec.artifactName = "Services hive resolver";
  servicesRec.sourceLogicalPath = "/Windows/System32/config/SYSTEM";
  const auto servicesDetails = service.describe(servicesRec, {[&](const QString &, QString &) { return systemHive; }});
  if (!servicesDetails.has_value() || servicesDetails->provider != "windows.services_v1") return 1;
  if (servicesDetails->serviceEntries.empty()) return 1;
  bool foundAcme = false;
  for (const auto &entry : servicesDetails->serviceEntries) {
    if (entry.serviceName == "AcmeSvc") {
      foundAcme = true;
      if (!entry.startType || *entry.startType != 2) return 1;
      if (!entry.serviceType || *entry.serviceType != 0x10) return 1;
      if (!entry.delayedAutoStart || !*entry.delayedAutoStart) return 1;
      if (entry.serviceDll.isEmpty()) return 1;
      if (entry.dependencies.isEmpty()) return 1;
      if (!entry.keyLastWriteTimestamp.has_value()) return 1;
    }
  }
  if (!foundAcme) return 1;
  const auto servicesJson = fie::cli::artifactDetailsToJson(*servicesDetails);
  if (!servicesJson.contains("service_entries") || servicesJson.value("service_entries").toArray().isEmpty()) return 1;
  servicesRec.details = servicesDetails;
  std::vector<fie::domain::ArtifactRecord> withServices{servicesRec};
  const auto serviceEvents = timeline.buildEvents(withServices);
  bool sawServiceConfig = false;
  for (const auto &e : serviceEvents) {
    if (e.eventType == "service_config_modified" || e.eventType == "service_config_observed") {
      sawServiceConfig = true;
      break;
    }
  }
  if (!sawServiceConfig) return 1;

  const auto noAppCompat = service.describe(appCompat, {[&](const QString &, QString &) { return noSelectHive; }});
  if (!noAppCompat.has_value()) return 1;
  if (noAppCompat->state != fie::domain::ArtifactParseState::Partial &&
      noAppCompat->state != fie::domain::ArtifactParseState::Unsupported) {
    return 1;
  }

  const auto truncatedAppCompatHive = buildSystemHiveWithTruncatedAppCompat();
  const auto truncatedAppCompat = service.describe(appCompat, {[&](const QString &, QString &) { return truncatedAppCompatHive; }});
  if (!truncatedAppCompat.has_value() || truncatedAppCompat->state != fie::domain::ArtifactParseState::Partial) return 1;

  const auto unsupportedAppCompatHive = buildSystemHiveWithUnsupportedAppCompatPayload();
  const auto unsupportedAppCompat = service.describe(appCompat, {[&](const QString &, QString &) { return unsupportedAppCompatHive; }});
  if (!unsupportedAppCompat.has_value() || unsupportedAppCompat->state != fie::domain::ArtifactParseState::Unsupported) return 1;

  const auto noServices = service.describe(servicesRec, {[&](const QString &, QString &) { return noSelectHive; }});
  if (!noServices.has_value()) return 1;
  if (noServices->state != fie::domain::ArtifactParseState::Partial &&
      noServices->state != fie::domain::ArtifactParseState::Unsupported) {
    return 1;
  }

  fie::domain::ArtifactRecord usbRec;
  usbRec.artifactName = "USB registry resolver";
  usbRec.sourceLogicalPath = "/Windows/System32/config/SYSTEM";
  const auto usbHive = buildSystemHiveForUsbStor();
  const auto usbDetails = service.describe(usbRec, {[&](const QString &, QString &) { return usbHive; }});
  if (!usbDetails.has_value() || usbDetails->provider != "windows.usb_registry_v1") return 1;
  if (usbDetails->usbDeviceEntries.empty()) return 1;
  const auto &usb0 = usbDetails->usbDeviceEntries.front();
  if (usb0.vendor != "SanDisk" || usb0.product != "Cruzer" || usb0.revision != "1.00") return 1;
  if (usb0.serialNumber != "123ABC") return 1;
  if (!usb0.keyLastWriteTimestamp.has_value()) return 1;

  const auto usbJson = fie::cli::artifactDetailsToJson(*usbDetails);
  if (!usbJson.contains("usb_device_entries") || usbJson.value("usb_device_entries").toArray().isEmpty()) return 1;

  usbRec.details = usbDetails;
  std::vector<fie::domain::ArtifactRecord> usbArtifacts{usbRec};
  const auto usbEvents = timeline.buildEvents(usbArtifacts);
  bool sawUsbTimed = false;
  for (const auto &e : usbEvents) {
    if (e.eventType == "usb_device_registry_modified" && e.timestamp.has_value()) {
      sawUsbTimed = true;
      break;
    }
  }
  if (!sawUsbTimed) return 1;

  const auto noUsbHive = buildSystemHiveWithoutUsbStor();
  const auto noUsb = service.describe(usbRec, {[&](const QString &, QString &) { return noUsbHive; }});
  if (!noUsb.has_value()) return 1;
  if (noUsb->state != fie::domain::ArtifactParseState::Unsupported &&
      noUsb->state != fie::domain::ArtifactParseState::Partial) {
    return 1;
  }

  const QByteArray truncatedUsbHive("regf", 4);
  const auto badUsb = service.describe(usbRec, {[&](const QString &, QString &) { return truncatedUsbHive; }});
  if (!badUsb.has_value() || badUsb->state != fie::domain::ArtifactParseState::Failed) return 1;

  return 0;
}
