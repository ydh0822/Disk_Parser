#include "ForensicImageExtractor/forensics/ArtifactDetailProviders.h"

#include <QByteArray>

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

QByteArray utf16(const QString &text) {
  return QByteArray(reinterpret_cast<const char *>(text.utf16()), text.size() * 2);
}

} // namespace

int runArtifactDetailProviderTests() {
  fie::forensics::ArtifactDetailService service;

  // Recycle Bin $I
  fie::domain::ArtifactRecord iRec;
  iRec.sourceLogicalPath = "/$Recycle.Bin/S-1-5-21-1/$IABC123";
  QByteArray iBytes;
  iBytes += le64(2);
  iBytes += le64(512);
  iBytes += le64(132537600000000000ULL);
  iBytes += utf16(QString("C:\\Users\\Alice\\Desktop\\x.txt"));
  iBytes += QByteArray("\0\0", 2);

  const auto iDetails = service.describe(iRec, {[&iBytes](const QString &, QString &) { return iBytes; }});
  if (!iDetails.has_value()) return 1;
  if (iDetails->state != fie::domain::ArtifactParseState::Parsed) return 1;
  if (iDetails->originalPath != "C:\\Users\\Alice\\Desktop\\x.txt") return 1;
  if (!iDetails->originalSizeBytes || *iDetails->originalSizeBytes != 512) return 1;

  // LNK summary
  fie::domain::ArtifactRecord lnkRec;
  lnkRec.sourceLogicalPath = "/Users/Alice/AppData/Roaming/Microsoft/Windows/Recent/test.lnk";
  QByteArray lnk(0x4C, 0);
  lnk.replace(0, 4, le32(0x4C));
  lnk.replace(0x14, 4, le32(0x80 | 0x10 | 0x20 | 0x40));
  const QString rel = "..\\target.exe";
  lnk += le16(static_cast<quint16>(rel.size()));
  lnk += utf16(rel);
  const QString work = "C:\\Temp";
  lnk += le16(static_cast<quint16>(work.size()));
  lnk += utf16(work);
  const QString args = "-n 1";
  lnk += le16(static_cast<quint16>(args.size()));
  lnk += utf16(args);

  const auto lnkDetails = service.describe(lnkRec, {[&lnk](const QString &, QString &) { return lnk; }});
  if (!lnkDetails.has_value()) return 1;
  if (lnkDetails->relativePath != rel || lnkDetails->workingDirectory != work || lnkDetails->commandLineArguments != args) return 1;

  // Prefetch summary
  fie::domain::ArtifactRecord pfRec;
  pfRec.sourceLogicalPath = "/Windows/Prefetch/CMD.EXE-1234.pf";
  QByteArray pf(0xE0, 0);
  pf.replace(0, 4, le32(30));
  pf.replace(4, 4, QByteArray("SCCA", 4));
  const QString exe = "CMD.EXE";
  const auto exeUtf16 = utf16(exe);
  pf.replace(16, exeUtf16.size(), exeUtf16);
  pf.replace(0xD0, 4, le32(7));
  pf.replace(0x80, 8, le64(132537600000000000ULL));

  const auto pfDetails = service.describe(pfRec, {[&pf](const QString &, QString &) { return pf; }});
  if (!pfDetails.has_value()) return 1;
  if (pfDetails->state == fie::domain::ArtifactParseState::Failed) return 1;
  if (pfDetails->executableName != "CMD.EXE") return 1;
  if (!pfDetails->runCount || *pfDetails->runCount != 7) return 1;
  if (pfDetails->lastRunTimestamps.empty()) return 1;

  // Unsupported type
  fie::domain::ArtifactRecord unsupported;
  unsupported.sourceLogicalPath = "/Users/Alice/NTUSER.DAT";
  if (service.describe(unsupported, {[](const QString &, QString &) { return QByteArray(); }}).has_value()) return 1;

  return 0;
}
