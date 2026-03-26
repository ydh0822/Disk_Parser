#include "ForensicImageExtractor/gui/ArtifactDetailsText.h"

int runArtifactDetailsTextTests() {
  const QString loading = fie::gui::formatArtifactDetailsText(std::nullopt, fie::gui::ArtifactDetailPanelState::Loading);
  if (!loading.contains("loading")) return 1;

  const QString unsupported =
      fie::gui::formatArtifactDetailsText(std::nullopt, fie::gui::ArtifactDetailPanelState::Unsupported);
  if (!unsupported.contains("unsupported")) return 1;

  fie::domain::ArtifactDetails details;
  details.provider = "windows.prefetch_summary";
  details.state = fie::domain::ArtifactParseState::Partial;
  details.summary = "Prefetch summary parsed";
  details.warnings = {"Truncated data"};
  details.executableName = "CMD.EXE";
  details.runCount = 2;
  details.registryRunMruEntries.push_back({.valueName = "a", .command = "cmd.exe", .mruPosition = 0});
  details.registryTypedPathEntries.push_back({.valueName = "url1", .path = "C:\\Windows"});
  details.registryRecentDocEntries.push_back({.valueName = "0", .documentName = "alpha.txt", .extensionGroup = ".txt", .mruPosition = 0});
  details.registryUserAssistEntries.push_back({.encodedName = "pzq.rkr", .decodedName = "cmd.exe", .runCount = 1, .lastExecution = std::nullopt});
  details.amcacheEntries.push_back({.programPath = "c:\\program files\\app\\app.exe", .fileName = "app.exe"});
  details.bamDamEntries.push_back({.source = "bam", .sid = "S-1", .executablePath = "C:\\Windows\\System32\\cmd.exe"});
  details.jumpListFormat = "automaticdestinations";
  details.jumpListVersion = 1;
  details.jumpListReportedEntryCount = 2;
  details.jumpListEntries.push_back({.entryIdentifier = "1111",
                                     .streamNumber = 1,
                                     .targetPath = "C:\\Users\\Alice\\Desktop\\Report.docx",
                                     .targetSummary = {},
                                     .lastAccessTimestamp = std::nullopt,
                                     .accessCount = 4,
                                     .pinned = true});
  details.appCompatCacheFormat = "utf16_path_scan_v1";
  details.appCompatCacheEntries.push_back({.sourceRegistryPath = "ControlSet001\\Control\\Session Manager\\AppCompatCache\\AppCompatCache",
                                           .entryIndex = 0,
                                           .executablePath = "C:\\Windows\\System32\\cmd.exe",
                                           .lastModifiedTimestamp = std::nullopt,
                                           .executionFlag = std::nullopt});
  details.serviceEntries.push_back({.serviceName = "AcmeSvc",
                                    .sourceRegistryPath = "ControlSet001\\Services\\AcmeSvc",
                                    .displayName = "Acme Service",
                                    .imagePath = "C:\\Program Files\\Acme\\svc.exe",
                                    .serviceDll = "C:\\Program Files\\Acme\\svc.dll",
                                    .startType = 2,
                                    .serviceType = 0x10,
                                    .objectName = "LocalSystem",
                                    .description = "Synthetic service",
                                    .delayedAutoStart = true,
                                    .loadOrderGroup = {},
                                    .dependencies = {"service:Tcpip"},
                                    .keyLastWriteTimestamp = std::nullopt});
  details.scheduledTaskEntries.push_back({.taskName = "ScheduledDefrag",
                                          .taskPath = "/Windows/System32/Tasks/Microsoft/Windows/Defrag/ScheduledDefrag",
                                          .uri = "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
                                          .author = "Microsoft",
                                          .description = {},
                                          .command = "C:\\Windows\\System32\\defrag.exe",
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
  details.werReportEntries.push_back({.reportPath = "/ProgramData/Microsoft/Windows/WER/ReportQueue/AppCrash_Test/Report.wer",
                                      .reportName = "Report.wer",
                                      .eventType = "APPCRASH",
                                      .applicationName = "example.exe",
                                      .applicationPath = "C:\\Program Files\\Example\\example.exe",
                                      .faultModuleName = "ntdll.dll",
                                      .faultModulePath = "C:\\Windows\\System32\\ntdll.dll",
                                      .exceptionCode = "c0000005",
                                      .bucketId = "12345",
                                      .cabId = {},
                                      .reportId = "abcd-1234",
                                      .response = "Not available",
                                      .problemSignatures = {"Sig[0]=example.exe"},
                                      .reportTimestamp = std::nullopt});
  details.usbDeviceEntries.push_back({.deviceClass = "USBSTOR",
                                      .enumRoot = "Enum\\USBSTOR",
                                      .deviceIdentifier = "Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00",
                                      .instanceId = "123ABC&0",
                                      .vendor = "SanDisk",
                                      .product = "Cruzer",
                                      .revision = "1.00",
                                      .serialNumber = "123ABC",
                                      .friendlyName = "SanDisk Cruzer USB Device",
                                      .parentIdPrefix = "7&1111111&0",
                                      .service = "USBSTOR",
                                      .classGuid = "{36fc9e60-c465-11cf-8056-444553540000}",
                                      .sourceRegistryPath = "ControlSet001\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00\\123ABC&0",
                                      .keyLastWriteTimestamp = std::nullopt});
  details.evtxLogEntries.push_back({.logName = "Security.evtx",
                                    .filePath = "/Windows/System32/winevt/Logs/Security.evtx",
                                    .recordCount = 1,
                                    .firstEventTimestamp = std::nullopt,
                                    .lastEventTimestamp = std::nullopt,
                                    .events = {}});

  const QString rendered = fie::gui::formatArtifactDetailsText(details, fie::gui::ArtifactDetailPanelState::Partial);
  if (!rendered.contains("windows.prefetch_summary")) return 1;
  if (!rendered.contains("Partial")) return 1;
  if (!rendered.contains("CMD.EXE")) return 1;
  if (!rendered.contains("Truncated data")) return 1;
  if (!rendered.contains("Registry RunMRU count: 1")) return 1;
  if (!rendered.contains("Registry TypedPaths count: 1")) return 1;
  if (!rendered.contains("Registry RecentDocs count: 1")) return 1;
  if (!rendered.contains("Registry UserAssist count: 1")) return 1;
  if (!rendered.contains("Amcache count : 1")) return 1;
  if (!rendered.contains("BAM/DAM count : 1")) return 1;
  if (!rendered.contains("Jump List format: automaticdestinations")) return 1;
  if (!rendered.contains("Jump List entries: 1")) return 1;
  if (!rendered.contains("AppCompatCache format: utf16_path_scan_v1")) return 1;
  if (!rendered.contains("AppCompatCache count: 1")) return 1;
  if (!rendered.contains("Services count: 1")) return 1;
  if (!rendered.contains("Services preview: AcmeSvc")) return 1;
  if (!rendered.contains("Scheduled Tasks count: 1")) return 1;
  if (!rendered.contains("Scheduled Tasks preview: ScheduledDefrag")) return 1;
  if (!rendered.contains("WER reports count: 1")) return 1;
  if (!rendered.contains("WER reports preview: Report.wer")) return 1;
  if (!rendered.contains("USB devices count: 1")) return 1;
  if (!rendered.contains("USB devices preview: SanDisk Cruzer USB Device")) return 1;
  if (!rendered.contains("EVTX logs count: 1")) return 1;
  if (!rendered.contains("EVTX logs preview: Security.evtx")) return 1;
  if (!rendered.contains("a=cmd.exe")) return 1;
  if (!rendered.contains("bam:C:\\Windows\\System32\\cmd.exe")) return 1;

  return 0;
}
