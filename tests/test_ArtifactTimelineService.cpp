#include "ForensicImageExtractor/forensics/ArtifactTimelineService.h"
#include "ForensicImageExtractor/cli/ArtifactTimelineJson.h"

int runArtifactTimelineServiceTests() {
  std::vector<fie::domain::ArtifactRecord> artifacts;

  fie::domain::ArtifactRecord recycle;
  recycle.category = "External";
  recycle.artifactName = "Recycle Bin";
  recycle.profile = "Alice";
  recycle.sourceLogicalPath = "/$Recycle.Bin/S-1/$I1";
  recycle.partitionIdentifier = "p1";
  recycle.fileSystemType = "NTFS";
  recycle.details = fie::domain::ArtifactDetails{};
  recycle.details->provider = "windows.recycle_bin_i";
  recycle.details->state = fie::domain::ArtifactParseState::Parsed;
  recycle.details->deletionTimestamp = QDateTime::fromString("2026-03-20T10:00:00Z", Qt::ISODate);
  recycle.details->originalPath = "C:/Users/Alice/Desktop/a.txt";
  recycle.details->originalSizeBytes = 123;
  artifacts.push_back(recycle);

  fie::domain::ArtifactRecord lnk;
  lnk.category = "External";
  lnk.artifactName = "LNK files";
  lnk.profile = "Alice";
  lnk.sourceLogicalPath = "/Users/Alice/Recent/a.lnk";
  lnk.partitionIdentifier = "p1";
  lnk.fileSystemType = "NTFS";
  lnk.details = fie::domain::ArtifactDetails{};
  lnk.details->provider = "windows.lnk_summary";
  lnk.details->state = fie::domain::ArtifactParseState::Partial;
  lnk.details->modifiedTimestamp = QDateTime::fromString("2026-03-18T10:00:00Z", Qt::ISODate);
  lnk.details->targetPath = "C:/Windows/System32/cmd.exe";
  lnk.details->warnings = {"truncated"};
  artifacts.push_back(lnk);

  fie::domain::ArtifactRecord pf;
  pf.category = "Execution";
  pf.artifactName = "Prefetch";
  pf.profile = "SYSTEM";
  pf.sourceLogicalPath = "/Windows/Prefetch/CMD.PF";
  pf.partitionIdentifier = "p1";
  pf.fileSystemType = "NTFS";
  pf.details = fie::domain::ArtifactDetails{};
  pf.details->provider = "windows.prefetch_summary";
  pf.details->state = fie::domain::ArtifactParseState::Failed;
  pf.details->executableName = "CMD.EXE";
  pf.details->runCount = 9;
  pf.details->error = "corrupt";
  artifacts.push_back(pf);

  fie::domain::ArtifactRecord browser;
  browser.category = "Browser";
  browser.artifactName = "Chrome History";
  browser.profile = "Alice";
  browser.sourceLogicalPath = "/Users/Alice/.../History";
  browser.partitionIdentifier = "p1";
  browser.fileSystemType = "NTFS";
  browser.details = fie::domain::ArtifactDetails{};
  browser.details->provider = "windows.chromium_history";
  browser.details->state = fie::domain::ArtifactParseState::Parsed;
  browser.details->browserVisits.push_back(
      {.timestamp = QDateTime::fromString("2026-03-19T10:00:00Z", Qt::ISODate), .url = "https://example.com", .title = "Example", .visitCount = 3});
  browser.details->browserDownloads.push_back(
      {.timestamp = QDateTime::fromString("2026-03-19T11:00:00Z", Qt::ISODate), .url = "https://example.com/a.zip", .targetPath = "C:/Users/Alice/Downloads/a.zip"});
  artifacts.push_back(browser);

  fie::domain::ArtifactRecord jumpList;
  jumpList.category = "External";
  jumpList.artifactName = "Jump Lists";
  jumpList.profile = "Alice";
  jumpList.sourceLogicalPath = "/Users/Alice/AppData/Roaming/Microsoft/Windows/Recent/x.automaticdestinations-ms";
  jumpList.partitionIdentifier = "p1";
  jumpList.fileSystemType = "NTFS";
  jumpList.details = fie::domain::ArtifactDetails{};
  jumpList.details->provider = "windows.jump_list_v1";
  jumpList.details->state = fie::domain::ArtifactParseState::Parsed;
  jumpList.details->jumpListEntries.push_back(
      {.entryIdentifier = "aaaabbbb",
       .streamNumber = 7,
       .targetPath = "C:/Users/Alice/Desktop/report.docx",
       .targetSummary = {},
       .lastAccessTimestamp = QDateTime::fromString("2026-03-21T10:00:00Z", Qt::ISODate),
       .accessCount = 5,
       .pinned = true});
  jumpList.details->jumpListEntries.push_back(
      {.entryIdentifier = "ccccdddd",
       .streamNumber = std::nullopt,
       .targetPath = {},
       .targetSummary = "LNK stream present: a",
       .lastAccessTimestamp = std::nullopt,
       .accessCount = std::nullopt,
       .pinned = std::nullopt});
  artifacts.push_back(jumpList);

  fie::domain::ArtifactRecord appCompat;
  appCompat.category = "Execution";
  appCompat.artifactName = "AppCompatCache resolver";
  appCompat.profile = "SYSTEM";
  appCompat.sourceLogicalPath = "/Windows/System32/config/SYSTEM";
  appCompat.partitionIdentifier = "p1";
  appCompat.fileSystemType = "NTFS";
  appCompat.details = fie::domain::ArtifactDetails{};
  appCompat.details->provider = "windows.appcompatcache_v1";
  appCompat.details->state = fie::domain::ArtifactParseState::Parsed;
  appCompat.details->appCompatCacheEntries.push_back(
      {.sourceRegistryPath = "ControlSet001\\Control\\Session Manager\\AppCompatCache\\AppCompatCache",
       .entryIndex = 0,
       .executablePath = "C:/Windows/System32/notepad.exe",
       .lastModifiedTimestamp = std::nullopt,
       .executionFlag = std::nullopt});
  appCompat.details->appCompatCacheEntries.push_back(
      {.sourceRegistryPath = "ControlSet001\\Control\\Session Manager\\AppCompatCache\\AppCompatCache",
       .entryIndex = 1,
       .executablePath = "C:/Windows/System32/calc.exe",
       .lastModifiedTimestamp = QDateTime::fromString("2026-03-22T10:00:00Z", Qt::ISODate),
       .executionFlag = true});
  artifacts.push_back(appCompat);

  fie::domain::ArtifactRecord services;
  services.category = "Persistence";
  services.artifactName = "Services hive resolver";
  services.profile = "SYSTEM";
  services.sourceLogicalPath = "/Windows/System32/config/SYSTEM";
  services.partitionIdentifier = "p1";
  services.fileSystemType = "NTFS";
  services.details = fie::domain::ArtifactDetails{};
  services.details->provider = "windows.services_v1";
  services.details->state = fie::domain::ArtifactParseState::Parsed;
  services.details->serviceEntries.push_back(
      {.serviceName = "AcmeSvc",
       .sourceRegistryPath = "ControlSet001\\Services\\AcmeSvc",
       .displayName = "Acme Service",
       .imagePath = "C:/Program Files/Acme/svc.exe",
       .serviceDll = "C:/Program Files/Acme/svc.dll",
       .startType = 2,
       .serviceType = 0x10,
       .objectName = "LocalSystem",
       .description = "Synthetic service",
       .delayedAutoStart = true,
       .loadOrderGroup = {},
       .dependencies = {"service:Tcpip"},
       .keyLastWriteTimestamp = std::nullopt});
  services.details->serviceEntries.push_back(
      {.serviceName = "TimedSvc",
       .sourceRegistryPath = "ControlSet001\\Services\\TimedSvc",
       .displayName = {},
       .imagePath = {},
       .serviceDll = {},
       .startType = std::nullopt,
       .serviceType = std::nullopt,
       .objectName = {},
       .description = {},
       .delayedAutoStart = std::nullopt,
       .loadOrderGroup = {},
       .dependencies = {},
       .keyLastWriteTimestamp = QDateTime::fromString("2026-03-23T10:00:00Z", Qt::ISODate)});
  artifacts.push_back(services);

  fie::domain::ArtifactRecord scheduledTask;
  scheduledTask.category = "Persistence";
  scheduledTask.artifactName = "Scheduled Task definitions";
  scheduledTask.profile = "SYSTEM";
  scheduledTask.sourceLogicalPath = "/Windows/System32/Tasks/Microsoft/Windows/Defrag/ScheduledDefrag";
  scheduledTask.partitionIdentifier = "p1";
  scheduledTask.fileSystemType = "NTFS";
  scheduledTask.details = fie::domain::ArtifactDetails{};
  scheduledTask.details->provider = "windows.scheduled_task_v1";
  scheduledTask.details->state = fie::domain::ArtifactParseState::Parsed;
  scheduledTask.details->scheduledTaskEntries.push_back(
      {.taskName = "ScheduledDefrag",
       .taskPath = "/Windows/System32/Tasks/Microsoft/Windows/Defrag/ScheduledDefrag",
       .uri = "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
       .author = "Microsoft",
       .description = {},
       .command = "C:/Windows/System32/defrag.exe",
       .arguments = "/C",
       .workingDirectory = {},
       .enabled = true,
       .hidden = false,
       .runLevel = "HighestAvailable",
       .userId = "S-1-5-18",
       .logonType = "ServiceAccount",
       .triggerSummaries = {"CalendarTrigger"},
       .repetitionSummary = {},
       .actionType = "Exec",
       .registrationDate = std::nullopt});
  scheduledTask.details->scheduledTaskEntries.push_back(
      {.taskName = "TimedTask",
       .taskPath = "/Windows/System32/Tasks/TimedTask",
       .uri = {},
       .author = {},
       .description = {},
       .command = {},
       .arguments = {},
       .workingDirectory = {},
       .enabled = std::nullopt,
       .hidden = std::nullopt,
       .runLevel = {},
       .userId = {},
       .logonType = {},
       .triggerSummaries = {},
       .repetitionSummary = {},
       .actionType = {},
       .registrationDate = QDateTime::fromString("2026-03-24T10:00:00Z", Qt::ISODate)});
  artifacts.push_back(scheduledTask);

  fie::domain::ArtifactRecord wer;
  wer.category = "Event/System";
  wer.artifactName = "WER report files";
  wer.profile = "SYSTEM";
  wer.sourceLogicalPath = "/ProgramData/Microsoft/Windows/WER/ReportQueue/AppCrash_x/Report.wer";
  wer.partitionIdentifier = "p1";
  wer.fileSystemType = "NTFS";
  wer.details = fie::domain::ArtifactDetails{};
  wer.details->provider = "windows.wer_v1";
  wer.details->state = fie::domain::ArtifactParseState::Parsed;
  wer.details->werReportEntries.push_back(
      {.reportPath = wer.sourceLogicalPath,
       .reportName = "Report.wer",
       .eventType = "APPCRASH",
       .applicationName = "app.exe",
       .applicationPath = "C:/app.exe",
       .faultModuleName = "ntdll.dll",
       .faultModulePath = "C:/Windows/System32/ntdll.dll",
       .exceptionCode = "c0000005",
       .bucketId = "12345",
       .cabId = {},
       .reportId = "A-B-C",
       .response = "Not available",
       .problemSignatures = {"Sig[0]=app.exe"},
       .reportTimestamp = std::nullopt});
  wer.details->werReportEntries.push_back(
      {.reportPath = "/ProgramData/Microsoft/Windows/WER/ReportArchive/AppCrash_y/report2.wer",
       .reportName = "report2.wer",
       .eventType = "APPCRASH",
       .applicationName = {},
       .applicationPath = {},
       .faultModuleName = {},
       .faultModulePath = {},
       .exceptionCode = {},
       .bucketId = {},
       .cabId = {},
       .reportId = {},
       .response = {},
       .problemSignatures = {},
       .reportTimestamp = QDateTime::fromString("2026-03-25T10:00:00Z", Qt::ISODate)});
  artifacts.push_back(wer);

  fie::domain::ArtifactRecord usb;
  usb.category = "External";
  usb.artifactName = "USB registry resolver";
  usb.profile = "SYSTEM";
  usb.sourceLogicalPath = "/Windows/System32/config/SYSTEM";
  usb.partitionIdentifier = "p1";
  usb.fileSystemType = "NTFS";
  usb.details = fie::domain::ArtifactDetails{};
  usb.details->provider = "windows.usb_registry_v1";
  usb.details->state = fie::domain::ArtifactParseState::Parsed;
  usb.details->usbDeviceEntries.push_back(
      {.deviceClass = "USBSTOR",
       .enumRoot = "Enum\\USBSTOR",
       .deviceIdentifier = "Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00",
       .instanceId = "123ABC&0",
       .vendor = "SanDisk",
       .product = "Cruzer",
       .revision = "1.00",
       .serialNumber = "123ABC",
       .friendlyName = "SanDisk Cruzer USB Device",
       .parentIdPrefix = {},
       .service = "USBSTOR",
       .classGuid = {},
       .sourceRegistryPath = "ControlSet002\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00\\123ABC&0",
       .keyLastWriteTimestamp = std::nullopt});
  usb.details->usbDeviceEntries.push_back(
      {.deviceClass = "USBSTOR",
       .enumRoot = "Enum\\USBSTOR",
       .deviceIdentifier = "Disk&Ven_Test&Prod_Drive&Rev_2.00",
       .instanceId = "456DEF&0",
       .vendor = "Test",
       .product = "Drive",
       .revision = "2.00",
       .serialNumber = "456DEF",
       .friendlyName = {},
       .parentIdPrefix = {},
       .service = {},
       .classGuid = {},
       .sourceRegistryPath = "ControlSet002\\Enum\\USBSTOR\\Disk&Ven_Test&Prod_Drive&Rev_2.00\\456DEF&0",
       .keyLastWriteTimestamp = QDateTime::fromString("2026-03-25T11:00:00Z", Qt::ISODate)});
  artifacts.push_back(usb);

  fie::domain::ArtifactRecord evtx;
  evtx.category = "Event/System";
  evtx.artifactName = "EVTX files";
  evtx.profile = "SYSTEM";
  evtx.sourceLogicalPath = "/Windows/System32/winevt/Logs/Security.evtx";
  evtx.partitionIdentifier = "p1";
  evtx.fileSystemType = "NTFS";
  evtx.details = fie::domain::ArtifactDetails{};
  evtx.details->provider = "windows.evtx_v1";
  evtx.details->state = fie::domain::ArtifactParseState::Parsed;
  fie::domain::ArtifactDetails::EvtxLogEntry evtxLog;
  evtxLog.logName = "Security.evtx";
  evtxLog.filePath = evtx.sourceLogicalPath;
  evtxLog.recordCount = 2;
  evtxLog.events.push_back(
      {.recordId = 100,
       .timestamp = QDateTime::fromString("2026-03-25T12:00:00Z", Qt::ISODate),
       .providerName = "Microsoft-Windows-Security-Auditing",
       .eventId = 4624,
       .level = 0,
       .computer = "HOST1",
       .opcode = 0,
       .task = 12544,
       .keywords = "0x8020000000000000",
       .eventData = {"TargetUserName=alice"}});
  evtxLog.events.push_back(
      {.recordId = 101,
       .timestamp = std::nullopt,
       .providerName = "Microsoft-Windows-Security-Auditing",
       .eventId = 4634,
       .level = 0,
       .computer = "HOST1",
       .opcode = std::nullopt,
       .task = std::nullopt,
       .keywords = {},
       .eventData = {}});
  evtx.details->evtxLogEntries.push_back(std::move(evtxLog));
  artifacts.push_back(evtx);

  fie::domain::ArtifactRecord sysmon;
  sysmon.category = "Event/System";
  sysmon.artifactName = "EVTX files";
  sysmon.profile = "SYSTEM";
  sysmon.sourceLogicalPath = "/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon/Operational.evtx";
  sysmon.partitionIdentifier = "p1";
  sysmon.fileSystemType = "NTFS";
  sysmon.details = fie::domain::ArtifactDetails{};
  sysmon.details->provider = "windows.evtx_v1";
  sysmon.details->state = fie::domain::ArtifactParseState::Parsed;
  fie::domain::ArtifactDetails::EvtxLogEntry sysmonLog;
  sysmonLog.logName = "Microsoft-Windows-Sysmon/Operational.evtx";
  sysmonLog.filePath = sysmon.sourceLogicalPath;
  sysmonLog.recordCount = 6;
  sysmonLog.events.push_back({.recordId = 9001,
                              .timestamp = QDateTime::fromString("2026-03-25T12:05:00Z", Qt::ISODate),
                              .providerName = "Microsoft-Windows-Sysmon",
                              .eventId = 1,
                              .level = 4,
                              .computer = "HOST1",
                              .eventData = {"ProcessGuid={1111-2222}", "ProcessId=4242", "Image=C:\\Windows\\System32\\cmd.exe",
                                            "CommandLine=cmd.exe /c whoami", "ParentImage=C:\\Windows\\explorer.exe"}});
  sysmonLog.events.push_back({.recordId = 9002,
                              .timestamp = QDateTime::fromString("2026-03-25T12:06:00Z", Qt::ISODate),
                              .providerName = "Microsoft-Windows-Sysmon",
                              .eventId = 3,
                              .level = 4,
                              .computer = "HOST1",
                              .eventData = {"Image=C:\\Windows\\System32\\curl.exe", "SourceIp=10.0.0.5",
                                            "DestinationIp=93.184.216.34", "DestinationPort=443", "Protocol=tcp"}});
  sysmonLog.events.push_back({.recordId = 9003,
                              .timestamp = std::nullopt,
                              .providerName = "Microsoft-Windows-Sysmon",
                              .eventId = 22,
                              .level = 4,
                              .computer = "HOST1",
                              .eventData = {"QueryName=example.org", "QueryStatus=0", "QueryResults=93.184.216.34"}});
  sysmonLog.events.push_back({.recordId = 9004,
                              .timestamp = QDateTime::fromString("2026-03-25T12:07:00Z", Qt::ISODate),
                              .providerName = "Microsoft-Windows-Sysmon",
                              .eventId = 10,
                              .level = 4,
                              .computer = "HOST1",
                              .eventData = {"SourceImage=C:\\Windows\\System32\\procexp.exe", "TargetImage=C:\\Windows\\System32\\lsass.exe",
                                            "GrantedAccess=0x1FFFFF", "CallTrace=ntdll.dll+1234"}});
  sysmonLog.events.push_back({.recordId = 9005,
                              .timestamp = QDateTime::fromString("2026-03-25T12:08:00Z", Qt::ISODate),
                              .providerName = "Microsoft-Windows-Sysmon",
                              .eventId = 11,
                              .level = 4,
                              .computer = "HOST1",
                              .eventData = {"TargetFilename=C:\\Temp\\dropper.bin", "Image=C:\\Windows\\System32\\cmd.exe"}});
  sysmonLog.events.push_back({.recordId = 9006,
                              .timestamp = QDateTime::fromString("2026-03-25T12:09:00Z", Qt::ISODate),
                              .providerName = "Microsoft-Windows-Sysmon",
                              .eventId = 25,
                              .level = 4,
                              .computer = "HOST1",
                              .eventData = {"Type=Image is replaced", "Image=C:\\Windows\\System32\\svchost.exe"}});
  sysmon.details->evtxLogEntries.push_back(std::move(sysmonLog));
  artifacts.push_back(sysmon);

  fie::domain::ArtifactRecord otherOperational = sysmon;
  otherOperational.sourceLogicalPath = "/Windows/System32/winevt/Logs/Microsoft-Windows-TaskScheduler/Operational.evtx";
  otherOperational.details = fie::domain::ArtifactDetails{};
  otherOperational.details->provider = "windows.evtx_v1";
  otherOperational.details->state = fie::domain::ArtifactParseState::Parsed;
  fie::domain::ArtifactDetails::EvtxLogEntry otherOpLog;
  otherOpLog.logName = "Microsoft-Windows-TaskScheduler/Operational.evtx";
  otherOpLog.filePath = otherOperational.sourceLogicalPath;
  otherOpLog.events.push_back({.recordId = 9100,
                               .timestamp = QDateTime::fromString("2026-03-25T12:10:00Z", Qt::ISODate),
                               .providerName = "Microsoft-Windows-TaskScheduler",
                               .eventId = 1,
                               .level = 4,
                               .computer = "HOST1",
                               .eventData = {"Image=C:\\Windows\\System32\\schtasks.exe"}});
  otherOperational.details->evtxLogEntries.push_back(std::move(otherOpLog));
  artifacts.push_back(otherOperational);

  fie::domain::ArtifactRecord srum;
  srum.category = "Event/System";
  srum.artifactName = "SRUM metadata probe";
  srum.profile = "SYSTEM";
  srum.sourceLogicalPath = "/Windows/System32/sru/SRUDB.dat";
  srum.partitionIdentifier = "p1";
  srum.fileSystemType = "NTFS";
  srum.details = fie::domain::ArtifactDetails{};
  srum.details->provider = "windows.srum_metadata_probe";
  srum.details->state = fie::domain::ArtifactParseState::Parsed;
  srum.details->srumEseSignatureValid = true;
  srum.details->srumPageSize = 4096;
  srum.details->srumTableEntries.push_back(
      {.tableId = "{973F5D5C-1D90-4944-BE8E-24B94231A174}", .tableName = "network_data_usage"});
  artifacts.push_back(srum);

  fie::domain::ArtifactRecord unsupported;
  unsupported.sourceLogicalPath = "/Users/Alice/NTUSER.DAT";
  artifacts.push_back(unsupported);

  // Unknown provider should still surface parse-status failures even without
  // a provider-specific timeline mapper.
  fie::domain::ArtifactRecord unknownFailed;
  unknownFailed.category = "Other";
  unknownFailed.artifactName = "Unknown artifact";
  unknownFailed.profile = "SYSTEM";
  unknownFailed.sourceLogicalPath = "/unknown/artifact.bin";
  unknownFailed.partitionIdentifier = "p1";
  unknownFailed.fileSystemType = "NTFS";
  unknownFailed.details = fie::domain::ArtifactDetails{};
  unknownFailed.details->provider = "windows.unknown_future_provider";
  unknownFailed.details->state = fie::domain::ArtifactParseState::Failed;
  unknownFailed.details->error = "synthetic failure";
  artifacts.push_back(unknownFailed);

  fie::forensics::ArtifactTimelineService svc;
  const auto events = svc.buildEvents(artifacts);
  if (events.size() < 6) return 1;

  // deterministic sort: timed first (lnk modified before recycle deletion)
  if (!events[0].timestamp.has_value()) return 1;
  if (events[0].eventType != "lnk_modified") return 1;
  if (events[1].eventType != "recycle_bin_deletion") return 1;

  bool sawFailedStatus = false;
  bool sawUnsupported = false;
  bool sawBrowserVisit = false;
  bool sawBrowserDownload = false;
  bool sawJumpListAccess = false;
  bool sawJumpListUntimed = false;
  bool sawAppCompatTimed = false;
  bool sawAppCompatUntimed = false;
  bool sawServiceTimed = false;
  bool sawServiceUntimed = false;
  bool sawTaskTimed = false;
  bool sawTaskUntimed = false;
  bool sawWerTimed = false;
  bool sawWerUntimed = false;
  bool sawUsbTimed = false;
  bool sawUsbUntimed = false;
  bool sawEvtxTimed = false;
  bool sawEvtxUntimed = false;
  bool sawSysmonProcessCreate = false;
  bool sawSysmonNetworkConnect = false;
  bool sawSysmonDnsTimed = false;
  bool sawSysmonDnsUntimed = false;
  bool sawSysmonProcessAccess = false;
  bool sawSysmonFileCreate = false;
  bool sawSysmonProcessTampering = false;
  bool sawNonSysmonOperationalMapped = false;
  bool sawUnknownFailedParseStatus = false;
  bool sawSrumTableObserved = false;
  bool sawUnexpectedSrumRowEvent = false;
  bool sawUnexpectedNonMetadataSrumEvent = false;
  for (const auto &e : events) {
    if (e.eventType == "artifact_parse_status" && e.parseState == fie::domain::ArtifactParseState::Failed) sawFailedStatus = true;
    if (e.sourceLogicalPath == unsupported.sourceLogicalPath) sawUnsupported = true;
    if (e.eventType == "browser_visit") sawBrowserVisit = true;
    if (e.eventType == "browser_download") sawBrowserDownload = true;
    if (e.eventType == "jump_list_access" && e.timestamp.has_value()) sawJumpListAccess = true;
    if (e.eventType == "jump_list_entry_observed" && !e.timestamp.has_value()) sawJumpListUntimed = true;
    if (e.eventType == "appcompatcache_entry" && e.timestamp.has_value()) sawAppCompatTimed = true;
    if (e.eventType == "appcompatcache_entry_observed" && !e.timestamp.has_value()) sawAppCompatUntimed = true;
    if (e.eventType == "service_config_modified" && e.timestamp.has_value()) sawServiceTimed = true;
    if (e.eventType == "service_config_observed" && !e.timestamp.has_value()) sawServiceUntimed = true;
    if (e.eventType == "scheduled_task_registered" && e.timestamp.has_value()) sawTaskTimed = true;
    if (e.eventType == "scheduled_task_observed" && !e.timestamp.has_value()) sawTaskUntimed = true;
    if (e.eventType == "wer_report_created" && e.timestamp.has_value()) sawWerTimed = true;
    if (e.eventType == "wer_report_observed" && !e.timestamp.has_value()) sawWerUntimed = true;
    if (e.eventType == "usb_device_registry_modified" && e.timestamp.has_value()) sawUsbTimed = true;
    if (e.eventType == "usb_device_observed" && !e.timestamp.has_value()) sawUsbUntimed = true;
    if (e.eventType == "evtx_event" && e.timestamp.has_value()) sawEvtxTimed = true;
    if (e.eventType == "evtx_event" && !e.timestamp.has_value()) sawEvtxUntimed = true;
    if (e.eventType == "sysmon_process_create") sawSysmonProcessCreate = true;
    if (e.eventType == "sysmon_network_connect") sawSysmonNetworkConnect = true;
    if (e.eventType == "sysmon_dns_query" && e.timestamp.has_value()) sawSysmonDnsTimed = true;
    if (e.eventType == "sysmon_dns_query" && !e.timestamp.has_value()) sawSysmonDnsUntimed = true;
    if (e.eventType == "sysmon_process_access") sawSysmonProcessAccess = true;
    if (e.eventType == "sysmon_file_create") sawSysmonFileCreate = true;
    if (e.eventType == "sysmon_process_tampering") sawSysmonProcessTampering = true;
    if (e.sourceLogicalPath.contains("TaskScheduler/Operational.evtx") && e.eventType.startsWith("sysmon_")) {
      sawNonSysmonOperationalMapped = true;
    }
    if (e.sourceLogicalPath == unknownFailed.sourceLogicalPath && e.eventType == "artifact_parse_status" &&
        e.parseState == fie::domain::ArtifactParseState::Failed) {
      sawUnknownFailedParseStatus = true;
    }
    if (e.eventType == "srum_metadata_table_observed" && e.sourceLogicalPath == srum.sourceLogicalPath &&
        !e.timestamp.has_value()) {
      sawSrumTableObserved = true;
    }
    if (e.eventType.startsWith("srum_row_")) sawUnexpectedSrumRowEvent = true;
    if (e.sourceLogicalPath == srum.sourceLogicalPath && e.eventType.startsWith("srum_") &&
        e.eventType != "srum_metadata_table_observed") {
      sawUnexpectedNonMetadataSrumEvent = true;
    }
  }
  if (!sawFailedStatus) return 1;
  if (sawUnsupported) return 1;
  if (!sawBrowserVisit || !sawBrowserDownload) return 1;
  if (!sawJumpListAccess || !sawJumpListUntimed) return 1;
  if (!sawAppCompatTimed || !sawAppCompatUntimed) return 1;
  if (!sawServiceTimed || !sawServiceUntimed) return 1;
  if (!sawTaskTimed || !sawTaskUntimed) return 1;
  if (!sawWerTimed || !sawWerUntimed) return 1;
  if (!sawUsbTimed || !sawUsbUntimed) return 1;
  if (!sawEvtxTimed || !sawEvtxUntimed) return 1;
  if (!sawSysmonProcessCreate || !sawSysmonNetworkConnect) return 1;
  if (!sawSysmonProcessAccess || !sawSysmonFileCreate || !sawSysmonProcessTampering) return 1;
  if (sawSysmonDnsTimed) return 1;
  if (!sawSysmonDnsUntimed) return 1;
  if (sawNonSysmonOperationalMapped) return 1;
  if (!sawUnknownFailedParseStatus) return 1;
  if (!sawSrumTableObserved) return 1;
  if (sawUnexpectedSrumRowEvent) return 1;
  if (sawUnexpectedNonMetadataSrumEvent) return 1;

  const auto json = fie::cli::artifactEventsToJsonArray(events);
  if (json.isEmpty()) return 1;
  const auto first = json.at(0).toObject();
  if (!first.contains("fields")) return 1;

  // null handling
  bool sawNull = false;
  for (const auto &v : json) {
    const auto o = v.toObject();
    if (o.value("timestamp").isNull()) {
      sawNull = true;
      break;
    }
  }
  if (!sawNull) return 1;

  return 0;
}
