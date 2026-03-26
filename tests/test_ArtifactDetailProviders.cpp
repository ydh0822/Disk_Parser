#include "ForensicImageExtractor/forensics/ArtifactDetailProviders.h"

#include <QByteArray>
#include <algorithm>

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

quint64 readLe64(const QByteArray &bytes, int off) {
  if (off < 0 || off + 8 > bytes.size()) return 0;
  quint64 value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<quint64>(static_cast<quint8>(bytes[off + i])) << (8 * i);
  }
  return value;
}

QByteArray utf16(const QString &text) {
  return QByteArray(reinterpret_cast<const char *>(text.utf16()), text.size() * 2);
}

void writeLe32(QByteArray &buf, int off, quint32 v) {
  if (off + 4 > buf.size()) buf.resize(off + 4);
  buf[off + 0] = static_cast<char>(v & 0xFF);
  buf[off + 1] = static_cast<char>((v >> 8) & 0xFF);
  buf[off + 2] = static_cast<char>((v >> 16) & 0xFF);
  buf[off + 3] = static_cast<char>((v >> 24) & 0xFF);
}

void writeLe64(QByteArray &buf, int off, quint64 v) {
  if (off + 8 > buf.size()) buf.resize(off + 8);
  for (int i = 0; i < 8; ++i) {
    buf[off + i] = static_cast<char>((v >> (8 * i)) & 0xFF);
  }
}

struct StreamSpec {
  QString name;
  QByteArray data;
};

void writeDirEntry(QByteArray &sector, int index, const QString &name, quint8 type, quint32 startSector, quint64 streamSize) {
  const int base = index * 128;
  QByteArray nameBytes = utf16(name);
  nameBytes += QByteArray("\0\0", 2);
  sector.replace(base, std::min(64, nameBytes.size()), nameBytes.left(64));
  sector[base + 64] = static_cast<char>(std::min(64, nameBytes.size()) & 0xFF);
  sector[base + 65] = static_cast<char>((std::min(64, nameBytes.size()) >> 8) & 0xFF);
  sector[base + 66] = static_cast<char>(type);
  writeLe32(sector, base + 116, startSector);
  writeLe64(sector, base + 120, streamSize);
}

QByteArray buildCfbf(const std::vector<StreamSpec> &streams, bool corruptFirstStreamFat = false) {
  QByteArray header(512, 0);
  header.replace(0, 8, QByteArray::fromHex("D0CF11E0A1B11AE1"));
  header.replace(30, 2, le16(9));
  header.replace(32, 2, le16(6));
  writeLe32(header, 44, 1);           // one FAT sector
  writeLe32(header, 48, 0);           // first dir sector
  writeLe32(header, 56, 4096);        // mini stream cutoff
  writeLe32(header, 60, 0xFFFFFFFEu); // no mini FAT
  writeLe32(header, 64, 0);
  writeLe32(header, 68, 0xFFFFFFFEu); // no DIFAT continuation
  writeLe32(header, 72, 0);
  const quint32 fatSectorId = static_cast<quint32>(streams.size() + 1);
  writeLe32(header, 76, fatSectorId);

  QByteArray dirSector(512, 0);
  writeDirEntry(dirSector, 0, "Root Entry", 5, 0xFFFFFFFEu, 0);
  for (int i = 0; i < static_cast<int>(streams.size()); ++i) {
    writeDirEntry(dirSector, i + 1, streams[i].name, 2, static_cast<quint32>(i + 1), streams[i].data.size());
  }

  QByteArray file = header;
  file += dirSector;
  for (const auto &stream : streams) {
    QByteArray padded = stream.data;
    if (padded.size() < 512) padded += QByteArray(512 - padded.size(), 0);
    file += padded.left(512);
  }

  QByteArray fatSector(512, 0xFF);
  writeLe32(fatSector, 0, 0xFFFFFFFEu); // dir sector end
  for (int i = 0; i < static_cast<int>(streams.size()); ++i) {
    writeLe32(fatSector, (i + 1) * 4, (corruptFirstStreamFat && i == 0) ? 1u : 0xFFFFFFFEu);
  }
  writeLe32(fatSector, fatSectorId * 4, 0xFFFFFFFDu); // FAT marker
  file += fatSector;

  return file;
}

QByteArray buildDestListEntry(int fixedSize,
                              quint32 streamNo,
                              const QString &targetPath,
                              bool includeTrustedMetrics,
                              quint32 accessCount = 0,
                              std::optional<bool> pinned = std::nullopt,
                              quint64 timestamp = 0) {
  QByteArray entry(fixedSize + targetPath.size() * 2, 0);
  entry.replace(0, 8, QByteArray::fromHex("1122334455667788"));
  writeLe32(entry, 88, streamNo);
  if (includeTrustedMetrics) {
    writeLe64(entry, 100, timestamp);
    if (pinned.has_value()) {
      writeLe32(entry, 104, *pinned ? 1 : 0);
    } else {
      writeLe32(entry, 104, 0xFFFFFFFFu);
    }
    writeLe32(entry, 108, accessCount);
  }
  entry.replace(fixedSize - 2, 2, le16(static_cast<quint16>(targetPath.size())));
  if (!targetPath.isEmpty()) entry.replace(fixedSize, targetPath.size() * 2, utf16(targetPath));
  return entry;
}

QByteArray buildDestList(const std::vector<QByteArray> &entries, bool truncateTail = false) {
  QByteArray out(32, 0);
  writeLe32(out, 0, 1);
  writeLe32(out, 4, static_cast<quint32>(entries.size()));
  for (const auto &entry : entries) out += entry;
  if (truncateTail && out.size() > 8) out.chop(8);
  return out;
}

QByteArray buildLinkedLnkFixture() {
  QByteArray lnk(0x4C, 0);
  lnk.replace(0, 4, le32(0x4C));
  lnk.replace(0x14, 4, le32(0x80 | 0x10 | 0x20));
  const QString rel = "..\\evidence\\payload.exe";
  lnk += le16(static_cast<quint16>(rel.size()));
  lnk += utf16(rel);
  const QString wd = "C:\\Users\\Alice\\Desktop";
  lnk += le16(static_cast<quint16>(wd.size()));
  lnk += utf16(wd);
  return lnk;
}

QByteArray buildEvtxRecord(quint64 recordId, quint64 filetime, const QByteArray &payload, bool corruptTrailer = false) {
  const int baseSize = 24 + payload.size() + 4;
  const int recSize = (baseSize + 7) & ~7;
  QByteArray rec(recSize, 0);
  writeLe32(rec, 0, static_cast<quint32>(recSize));
  writeLe64(rec, 8, recordId);
  writeLe64(rec, 16, filetime);
  rec.replace(24, payload.size(), payload);
  writeLe32(rec, recSize - 4, static_cast<quint32>(corruptTrailer ? recSize - 8 : recSize));
  return rec;
}

QByteArray buildEvtxNameRefFixturePayload(const QString &provider,
                                          quint16 eventId,
                                          quint8 level,
                                          const QString &computer,
                                          quint16 opcode,
                                          quint16 task,
                                          quint64 keywords,
                                          quint64 filetime,
                                          const QString &dataKey = {},
                                          const QString &dataValue = {}) {
  const QString timestampIso = QDateTime::fromSecsSinceEpoch(static_cast<qint64>((filetime / 10000000ULL) - 11644473600ULL), Qt::UTC)
                                   .toString(Qt::ISODate);
  const QString keywordText = QString("0x%1").arg(QString::number(keywords, 16).toUpper());

  const std::vector<QString> names = {"Event",      "System",   "Provider", "Name",      "TimeCreated",
                                      "SystemTime", "EventID",  "Level",    "Opcode",    "Task",
                                      "Keywords",   "Computer", "EventData","Data"};
  QMap<QString, quint32> nameOffsets;
  QByteArray nameTable;

  auto nameRecordSize = [](const QString &s) { return 4 + 2 + 2 + (s.size() * 2) + 2; };

  QByteArray body;
  auto writeNameRefToken = [&](quint8 token, const QString &name, bool open = false) {
    body.push_back(static_cast<char>(token));
    if (open) {
      body += le16(0);
      body += le32(0);
    }
    body += le32(0); // patched later with true name offset
    nameOffsets.insertMulti(name, static_cast<quint32>(body.size() - 4));
  };
  auto writeValueText = [&](const QString &value) {
    body.push_back(static_cast<char>(0x05));
    body += le16(static_cast<quint16>(value.size()));
    body += utf16(value);
  };
  auto writeAttribute = [&](const QString &attrName, const QString &attrValue) {
    writeNameRefToken(0x06, attrName, false);
    writeValueText(attrValue);
  };
  auto writeOpen = [&](const QString &name) { writeNameRefToken(0x01, name, true); };
  auto writeCloseStart = [&]() { body.push_back(static_cast<char>(0x02)); };
  auto writeEnd = [&]() { body.push_back(static_cast<char>(0x04)); };

  writeOpen("Event");
  writeCloseStart();
  writeOpen("System");
  writeCloseStart();
  writeOpen("Provider");
  writeAttribute("Name", provider);
  writeCloseStart();
  writeEnd();
  writeOpen("TimeCreated");
  writeAttribute("SystemTime", timestampIso);
  writeCloseStart();
  writeEnd();
  writeOpen("EventID");
  writeCloseStart();
  writeValueText(QString::number(eventId));
  writeEnd();
  writeOpen("Level");
  writeCloseStart();
  writeValueText(QString::number(level));
  writeEnd();
  writeOpen("Opcode");
  writeCloseStart();
  writeValueText(QString::number(opcode));
  writeEnd();
  writeOpen("Task");
  writeCloseStart();
  writeValueText(QString::number(task));
  writeEnd();
  writeOpen("Keywords");
  writeCloseStart();
  writeValueText(keywordText);
  writeEnd();
  writeOpen("Computer");
  writeCloseStart();
  writeValueText(computer);
  writeEnd();
  writeEnd(); // System

  if (!dataKey.isEmpty() || !dataValue.isEmpty()) {
    writeOpen("EventData");
    writeCloseStart();
    writeOpen("Data");
    writeAttribute("Name", dataKey);
    writeCloseStart();
    writeValueText(dataValue);
    writeEnd();
    writeEnd();
  }
  writeEnd(); // Event
  body.push_back(static_cast<char>(0x00)); // end-of-stream marker

  const int nameTableStart = 4 + body.size();
  QMap<QString, quint32> trueNameOffsets;
  int cur = nameTableStart;
  for (const auto &n : names) {
    trueNameOffsets[n] = static_cast<quint32>(cur);
    cur += nameRecordSize(n);
  }

  for (auto it = nameOffsets.constBegin(); it != nameOffsets.constEnd(); ++it) {
    const quint32 off = trueNameOffsets.value(it.key());
    const int patchAt = static_cast<int>(it.value());
    body[patchAt + 0] = static_cast<char>(off & 0xFF);
    body[patchAt + 1] = static_cast<char>((off >> 8) & 0xFF);
    body[patchAt + 2] = static_cast<char>((off >> 16) & 0xFF);
    body[patchAt + 3] = static_cast<char>((off >> 24) & 0xFF);
  }

  for (int i = 0; i < names.size(); ++i) {
    const QString &name = names[static_cast<size_t>(i)];
    const quint32 next = (i + 1 < static_cast<int>(names.size())) ? trueNameOffsets[names[static_cast<size_t>(i + 1)]] : 0;
    nameTable += le32(next);
    nameTable += le16(0); // hash unused in tests
    nameTable += le16(static_cast<quint16>(name.size()));
    nameTable += utf16(name);
    nameTable += QByteArray("\0\0", 2);
  }

  QByteArray payload;
  payload += QByteArray::fromHex("0F010100");
  payload += body;
  payload += nameTable;
  return payload;
}

QByteArray buildEvtxNameRefSubstitutionPayload(const QString &provider,
                                               quint16 eventId,
                                               const QString &computer,
                                               const QString &dataKey,
                                               const QString &dataValue) {
  const std::vector<QString> names = {"Event",     "System",   "Provider", "Name",   "EventID",
                                      "Computer",  "EventData", "Data"};
  QByteArray body;
  QMap<QString, quint32> nameOffsets;
  auto writeNameRefToken = [&](quint8 token, const QString &name, bool open = false) {
    body.push_back(static_cast<char>(token));
    if (open) {
      body += le16(0);
      body += le32(0);
    }
    body += le32(0);
    nameOffsets.insertMulti(name, static_cast<quint32>(body.size() - 4));
  };
  auto writeSubst = [&](quint16 idx) {
    body.push_back(static_cast<char>(0x0D));
    body += le16(idx);
    body.push_back(static_cast<char>(0x01));
    body.push_back('\0');
  };
  auto writeOpen = [&](const QString &name) { writeNameRefToken(0x01, name, true); };
  auto closeStart = [&]() { body.push_back(static_cast<char>(0x02)); };
  auto end = [&]() { body.push_back(static_cast<char>(0x04)); };
  auto writeAttributeSubst = [&](const QString &name, quint16 idx) {
    writeNameRefToken(0x06, name, false);
    writeSubst(idx);
  };

  // inline template-style substitution table token 0x0C
  body.push_back(static_cast<char>(0x0C));
  body.push_back('\0');
  body += le16(5);
  auto addSub = [&](const QString &v) {
    const QByteArray raw = utf16(v);
    body += le16(static_cast<quint16>(raw.size()));
    body.push_back(static_cast<char>(0x01));
    body.push_back('\0');
    body += raw;
  };
  addSub(provider);                // 0
  addSub(QString::number(eventId)); // 1
  addSub(computer);               // 2
  addSub(dataKey);                // 3
  addSub(dataValue);              // 4

  writeOpen("Event");
  closeStart();
  writeOpen("System");
  closeStart();
  writeOpen("Provider");
  writeAttributeSubst("Name", 0);
  closeStart();
  end();
  writeOpen("EventID");
  closeStart();
  writeSubst(1);
  end();
  writeOpen("Computer");
  closeStart();
  writeSubst(2);
  end();
  end(); // System
  writeOpen("EventData");
  closeStart();
  writeOpen("Data");
  writeAttributeSubst("Name", 3);
  closeStart();
  writeSubst(4);
  end();
  end();
  end(); // Event
  body.push_back('\0');

  auto nameRecordSize = [](const QString &s) { return 4 + 2 + 2 + (s.size() * 2) + 2; };
  const int tableStart = 4 + body.size();
  QMap<QString, quint32> trueOffsets;
  int cur = tableStart;
  for (const auto &n : names) {
    trueOffsets[n] = static_cast<quint32>(cur);
    cur += nameRecordSize(n);
  }
  for (auto it = nameOffsets.constBegin(); it != nameOffsets.constEnd(); ++it) {
    const quint32 off = trueOffsets.value(it.key());
    const int pos = static_cast<int>(it.value());
    body[pos + 0] = static_cast<char>(off & 0xFF);
    body[pos + 1] = static_cast<char>((off >> 8) & 0xFF);
    body[pos + 2] = static_cast<char>((off >> 16) & 0xFF);
    body[pos + 3] = static_cast<char>((off >> 24) & 0xFF);
  }
  QByteArray nameTable;
  for (int i = 0; i < names.size(); ++i) {
    const QString &name = names[static_cast<size_t>(i)];
    const quint32 next = (i + 1 < static_cast<int>(names.size())) ? trueOffsets[names[static_cast<size_t>(i + 1)]] : 0;
    nameTable += le32(next);
    nameTable += le16(0);
    nameTable += le16(static_cast<quint16>(name.size()));
    nameTable += utf16(name);
    nameTable += QByteArray("\0\0", 2);
  }
  QByteArray payload;
  payload += QByteArray::fromHex("0F010100");
  payload += body;
  payload += nameTable;
  return payload;
}

QByteArray buildEvtxFixture(const std::vector<QByteArray> &records) {
  QByteArray out(4096, 0);
  out.replace(0, 7, QByteArray("ElfFile", 7));
  QByteArray chunk(65536, 0);
  chunk.replace(0, 7, QByteArray("ElfChnk", 7));
  quint32 cursor = 0x200;
  quint32 lastOffset = cursor;
  quint64 firstRecordId = 0;
  quint64 lastRecordId = 0;
  for (const auto &rec : records) {
    if (cursor + static_cast<quint32>(rec.size()) >= 65536) break;
    if (firstRecordId == 0) firstRecordId = readLe64(rec, 8);
    lastRecordId = readLe64(rec, 8);
    chunk.replace(static_cast<int>(cursor), rec.size(), rec);
    lastOffset = cursor;
    cursor += static_cast<quint32>(rec.size());
  }
  writeLe64(chunk, 0x08, firstRecordId);
  writeLe64(chunk, 0x10, lastRecordId);
  writeLe32(chunk, 0x28, 0x200);
  writeLe32(chunk, 0x2C, lastOffset);
  writeLe32(chunk, 0x30, cursor);
  out += chunk;
  return out;
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

  // LNK summary provider
  fie::domain::ArtifactRecord lnkRec;
  lnkRec.sourceLogicalPath = "/Users/Alice/AppData/Roaming/Microsoft/Windows/Recent/test.lnk";
  QByteArray lnk = buildLinkedLnkFixture();
  const auto lnkDetails = service.describe(lnkRec, {[&lnk](const QString &, QString &) { return lnk; }});
  if (!lnkDetails.has_value()) return 1;
  if (lnkDetails->relativePath.isEmpty() || lnkDetails->workingDirectory.isEmpty()) return 1;

  // Prefetch summary
  fie::domain::ArtifactRecord pfRec;
  pfRec.sourceLogicalPath = "/Windows/Prefetch/CMD.EXE-1234.pf";
  QByteArray pf(0xE0, 0);
  pf.replace(0, 4, le32(30));
  pf.replace(4, 4, QByteArray("SCCA", 4));
  const QString exe = "CMD.EXE";
  pf.replace(16, utf16(exe).size(), utf16(exe));
  pf.replace(0xD0, 4, le32(7));
  pf.replace(0x80, 8, le64(132537600000000000ULL));
  const auto pfDetails = service.describe(pfRec, {[&pf](const QString &, QString &) { return pf; }});
  if (!pfDetails.has_value()) return 1;
  if (!pfDetails->runCount || *pfDetails->runCount != 7) return 1;

  // Jump List AutomaticDestinations: 114-byte trusted layout
  fie::domain::ArtifactRecord jl114Rec;
  jl114Rec.sourceLogicalPath = "/Users/Alice/AppData/Roaming/Microsoft/Windows/Recent/a.automaticdestinations-ms";
  const auto dest114 = buildDestList({buildDestListEntry(114, 1, "C:\\Users\\Alice\\Desktop\\Report.docx", true, 3, true,
                                                          132537600000000000ULL)});
  const auto file114 = buildCfbf({{"DestList", dest114}});
  const auto jl114 = service.describe(jl114Rec, {[&file114](const QString &, QString &) { return file114; }});
  if (!jl114.has_value()) return 1;
  if (jl114->state == fie::domain::ArtifactParseState::Failed) return 1;
  if (jl114->jumpListEntries.size() != 1) return 1;
  if (!jl114->jumpListEntries.front().lastAccessTimestamp.has_value()) return 1;
  if (!jl114->jumpListEntries.front().accessCount || *jl114->jumpListEntries.front().accessCount != 3) return 1;
  if (!jl114->jumpListEntries.front().pinned || !*jl114->jumpListEntries.front().pinned) return 1;

  // Jump List AutomaticDestinations: 128-byte trust-limited layout
  fie::domain::ArtifactRecord jl128Rec;
  jl128Rec.sourceLogicalPath = "/Users/Alice/AppData/Roaming/Microsoft/Windows/Recent/b.automaticdestinations-ms";
  const auto dest128 = buildDestList({buildDestListEntry(128, 2, "C:\\Temp\\alpha.txt", false)});
  const auto file128 = buildCfbf({{"DestList", dest128}});
  const auto jl128 = service.describe(jl128Rec, {[&file128](const QString &, QString &) { return file128; }});
  if (!jl128.has_value()) return 1;
  if (jl128->jumpListEntries.size() != 1) return 1;
  if (jl128->jumpListEntries.front().lastAccessTimestamp.has_value()) return 1;
  if (jl128->jumpListEntries.front().accessCount.has_value()) return 1;
  if (jl128->jumpListEntries.front().pinned.has_value()) return 1;

  // Jump List DestList truncated -> Partial
  fie::domain::ArtifactRecord jlTruncRec;
  jlTruncRec.sourceLogicalPath = "/Users/Alice/AppData/Roaming/Microsoft/Windows/Recent/c.automaticdestinations-ms";
  const auto trunc = buildDestList({buildDestListEntry(114, 1, "C:\\x.txt", true)}, true);
  const auto truncFile = buildCfbf({{"DestList", trunc}});
  const auto jlTrunc = service.describe(jlTruncRec, {[&truncFile](const QString &, QString &) { return truncFile; }});
  if (!jlTrunc.has_value()) return 1;
  if (jlTrunc->state != fie::domain::ArtifactParseState::Partial) return 1;

  // Jump List DestList missing -> Partial
  fie::domain::ArtifactRecord jlMissingRec;
  jlMissingRec.sourceLogicalPath = "/Users/Alice/AppData/Roaming/Microsoft/Windows/Recent/d.automaticdestinations-ms";
  const auto missingFile = buildCfbf({{"1", buildLinkedLnkFixture()}});
  const auto jlMissing = service.describe(jlMissingRec, {[&missingFile](const QString &, QString &) { return missingFile; }});
  if (!jlMissing.has_value()) return 1;
  if (jlMissing->state != fie::domain::ArtifactParseState::Partial) return 1;

  // linked LNK stream enriches missing target path
  fie::domain::ArtifactRecord jlEnrichRec;
  jlEnrichRec.sourceLogicalPath = "/Users/Alice/AppData/Roaming/Microsoft/Windows/Recent/e.automaticdestinations-ms";
  const auto enrichDest = buildDestList({buildDestListEntry(114, 1, "", true)});
  const auto enrichFile = buildCfbf({{"DestList", enrichDest}, {"1", buildLinkedLnkFixture()}});
  const auto jlEnrich = service.describe(jlEnrichRec, {[&enrichFile](const QString &, QString &) { return enrichFile; }});
  if (!jlEnrich.has_value()) return 1;
  if (jlEnrich->jumpListEntries.empty()) return 1;
  if (jlEnrich->jumpListEntries.front().targetSummary.isEmpty()) return 1;

  // linked stream referenced but absent
  fie::domain::ArtifactRecord jlMissingLinkRec;
  jlMissingLinkRec.sourceLogicalPath = "/Users/Alice/AppData/Roaming/Microsoft/Windows/Recent/f.automaticdestinations-ms";
  const auto missingLinkDest = buildDestList({buildDestListEntry(114, 99, "", true)});
  const auto missingLinkFile = buildCfbf({{"DestList", missingLinkDest}});
  const auto jlMissingLink =
      service.describe(jlMissingLinkRec, {[&missingLinkFile](const QString &, QString &) { return missingLinkFile; }});
  if (!jlMissingLink.has_value()) return 1;
  bool sawMissingLinkWarning = false;
  for (const auto &w : jlMissingLink->warnings) {
    if (w.contains("was not found")) {
      sawMissingLinkWarning = true;
      break;
    }
  }
  if (!sawMissingLinkWarning) return 1;

  // malformed FAT chain
  fie::domain::ArtifactRecord jlBadFatRec;
  jlBadFatRec.sourceLogicalPath = "/Users/Alice/AppData/Roaming/Microsoft/Windows/Recent/g.automaticdestinations-ms";
  const auto badFatFile = buildCfbf({{"DestList", dest114}}, true);
  const auto jlBadFat = service.describe(jlBadFatRec, {[&badFatFile](const QString &, QString &) { return badFatFile; }});
  if (!jlBadFat.has_value()) return 1;
  if (jlBadFat->state != fie::domain::ArtifactParseState::Failed) return 1;

  // Jump List CustomDestinations deferred
  fie::domain::ArtifactRecord customRec;
  customRec.sourceLogicalPath = "/Users/Alice/AppData/Roaming/Microsoft/Windows/Recent/b.customdestinations-ms";
  const auto customDetails = service.describe(customRec, {[](const QString &, QString &) { return QByteArray(); }});
  if (!customDetails.has_value()) return 1;
  if (customDetails->state != fie::domain::ArtifactParseState::Unsupported) return 1;

  // Scheduled Task XML parse
  fie::domain::ArtifactRecord taskRec;
  taskRec.artifactName = "Scheduled Task definitions";
  taskRec.sourceLogicalPath = "/Windows/System32/Tasks/Microsoft/Windows/Defrag/ScheduledDefrag";
  const QByteArray taskXml =
      "<Task><RegistrationInfo><URI>\\\\Microsoft\\\\Windows\\\\Defrag\\\\ScheduledDefrag</URI>"
      "<Author>Microsoft</Author><Date>2026-03-01T10:00:00Z</Date></RegistrationInfo>"
      "<Principals><Principal><UserId>S-1-5-18</UserId><LogonType>ServiceAccount</LogonType>"
      "<RunLevel>HighestAvailable</RunLevel></Principal></Principals>"
      "<Settings><Enabled>true</Enabled><Hidden>false</Hidden></Settings>"
      "<Triggers><CalendarTrigger><StartBoundary>2026-03-02T00:00:00Z</StartBoundary></CalendarTrigger></Triggers>"
      "<Actions><Exec><Command>C:\\\\Windows\\\\System32\\\\defrag.exe</Command><Arguments>/C</Arguments></Exec></Actions></Task>";
  const auto taskDetails = service.describe(taskRec, {[&taskXml](const QString &, QString &) { return taskXml; }});
  if (!taskDetails.has_value()) return 1;
  if (taskDetails->provider != "windows.scheduled_task_v1") return 1;
  if (taskDetails->scheduledTaskEntries.empty()) return 1;
  if (taskDetails->scheduledTaskEntries.front().command.isEmpty()) return 1;
  if (!taskDetails->scheduledTaskEntries.front().registrationDate.has_value()) return 1;

  // Scheduled Task partial XML
  const QByteArray taskPartialXml = "<Task><Actions><Exec><Command>cmd.exe</Command></Exec></Actions></Task>";
  const auto taskPartial = service.describe(taskRec, {[&taskPartialXml](const QString &, QString &) { return taskPartialXml; }});
  if (!taskPartial.has_value()) return 1;
  if (taskPartial->state == fie::domain::ArtifactParseState::Failed) return 1;

  // Scheduled Task UTF-16 XML with BOM (encoding-aware regression)
  const QString taskUtf16Text = "<Task><Actions><Exec><Command>powershell.exe</Command></Exec></Actions></Task>";
  QByteArray taskUtf16("\xFF\xFE", 2);
  taskUtf16 += utf16(taskUtf16Text);
  const auto taskUtf16Details = service.describe(taskRec, {[&taskUtf16](const QString &, QString &) { return taskUtf16; }});
  if (!taskUtf16Details.has_value()) return 1;
  if (taskUtf16Details->state == fie::domain::ArtifactParseState::Failed) return 1;
  if (taskUtf16Details->scheduledTaskEntries.empty()) return 1;
  if (taskUtf16Details->scheduledTaskEntries.front().command != "powershell.exe") return 1;

  // Scheduled Task invalid XML
  const QByteArray taskBadXml = "<Task><Actions><Exec>";
  const auto taskFailed = service.describe(taskRec, {[&taskBadXml](const QString &, QString &) { return taskBadXml; }});
  if (!taskFailed.has_value()) return 1;
  if (taskFailed->state != fie::domain::ArtifactParseState::Failed) return 1;

  // Legacy/non-XML task payload unsupported
  const QByteArray taskBinary("MZ....", 6);
  const auto taskUnsupported = service.describe(taskRec, {[&taskBinary](const QString &, QString &) { return taskBinary; }});
  if (!taskUnsupported.has_value()) return 1;
  if (taskUnsupported->state != fie::domain::ArtifactParseState::Unsupported) return 1;

  // WER parse with conservative key-value extraction
  fie::domain::ArtifactRecord werRec;
  werRec.artifactName = "WER report files";
  werRec.sourceLogicalPath = "/ProgramData/Microsoft/Windows/WER/ReportQueue/AppCrash_Test/Report.wer";
  const QByteArray werText =
      "[Version]\r\n"
      "EventType=APPCRASH\r\n"
      "AppName=example.exe\r\n"
      "AppPath=C:\\\\Program Files\\\\Example\\\\example.exe\r\n"
      "ModName=ntdll.dll\r\n"
      "ExceptionCode=c0000005\r\n"
      "Bucket=12345\r\n"
      "ReportIdentifier=abcd-1234\r\n"
      "EventTime=133876560000000000\r\n"
      "Sig[0]=example.exe\r\n";
  const auto werDetails = service.describe(werRec, {[&werText](const QString &, QString &) { return werText; }});
  if (!werDetails.has_value()) return 1;
  if (werDetails->provider != "windows.wer_v1") return 1;
  if (werDetails->werReportEntries.empty()) return 1;
  if (werDetails->werReportEntries.front().applicationName != "example.exe") return 1;
  if (!werDetails->werReportEntries.front().reportTimestamp.has_value()) return 1;

  // WER partial parse with sparse fields
  const QByteArray werPartialText = "EventType=APPHANG\r\n";
  const auto werPartial = service.describe(werRec, {[&werPartialText](const QString &, QString &) { return werPartialText; }});
  if (!werPartial.has_value()) return 1;
  if (werPartial->state == fie::domain::ArtifactParseState::Failed) return 1;

  // WER unsupported binary/deferred payload
  const QByteArray werBinary("MZ....", 6);
  const auto werUnsupported = service.describe(werRec, {[&werBinary](const QString &, QString &) { return werBinary; }});
  if (!werUnsupported.has_value()) return 1;
  if (werUnsupported->state != fie::domain::ArtifactParseState::Unsupported) return 1;

  // EVTX structural parse from tokenized name-ref BinXML fixture
  fie::domain::ArtifactRecord evtxRec;
  evtxRec.artifactName = "EVTX files";
  evtxRec.sourceLogicalPath = "/Windows/System32/winevt/Logs/Security.evtx";
  const auto evtxBytes = buildEvtxFixture({
      buildEvtxRecord(100, 133876560000000000ULL,
                      buildEvtxNameRefFixturePayload("Microsoft-Windows-Security-Auditing", 4624, 0, "HOST1", 0, 12544,
                                                     0x8020000000000000ULL, 133876560000000000ULL, "TargetUserName",
                                                     "alice")),
      buildEvtxRecord(101, 0ULL,
                      buildEvtxNameRefFixturePayload("Microsoft-Windows-Security-Auditing", 4634, 0, "HOST1", 0, 0, 0,
                                                     0ULL)),
  });
  const auto evtxDetails = service.describe(evtxRec, {[&evtxBytes](const QString &, QString &) { return evtxBytes; }});
  if (!evtxDetails.has_value()) return 1;
  if (evtxDetails->provider != "windows.evtx_v1") return 1;
  if (evtxDetails->evtxLogEntries.empty()) return 1;
  if (!evtxDetails->evtxLogEntries.front().recordCount || *evtxDetails->evtxLogEntries.front().recordCount < 2) return 1;
  if (evtxDetails->evtxLogEntries.front().events.front().providerName.isEmpty()) return 1;
  if (!evtxDetails->evtxLogEntries.front().events.front().timestamp.has_value()) return 1;
  if (evtxDetails->evtxLogEntries.front().events.front().eventData.empty()) return 1;
  fie::domain::ArtifactRecord sysmonEvtxRec = evtxRec;
  sysmonEvtxRec.sourceLogicalPath = "/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon/Operational.evtx";

  // EVTX Sysmon substitution-style payload fixtures (IDs 1/3/10/11/22/25)
  const auto sysmonFixture = buildEvtxFixture(
      {buildEvtxRecord(301, 133876560000000000ULL,
                       buildEvtxNameRefSubstitutionPayload("Microsoft-Windows-Sysmon", 1, "HOST1", "Image",
                                                           "C:\\Windows\\System32\\cmd.exe")),
       buildEvtxRecord(302, 133876560100000000ULL,
                       buildEvtxNameRefSubstitutionPayload("Microsoft-Windows-Sysmon", 3, "HOST1", "DestinationIp",
                                                           "93.184.216.34")),
       buildEvtxRecord(303, 133876560200000000ULL,
                       buildEvtxNameRefSubstitutionPayload("Microsoft-Windows-Sysmon", 10, "HOST1", "GrantedAccess",
                                                           "0x1FFFFF")),
       buildEvtxRecord(304, 133876560300000000ULL,
                       buildEvtxNameRefSubstitutionPayload("Microsoft-Windows-Sysmon", 11, "HOST1", "TargetFilename",
                                                           "C:\\Temp\\dropper.bin")),
       buildEvtxRecord(305, 0ULL,
                       buildEvtxNameRefSubstitutionPayload("Microsoft-Windows-Sysmon", 22, "HOST1", "QueryName",
                                                           "example.org")),
       buildEvtxRecord(306, 133876560400000000ULL,
                       buildEvtxNameRefSubstitutionPayload("Microsoft-Windows-Sysmon", 25, "HOST1", "Type",
                                                           "Image is replaced"))});
  const auto sysmonFixtureDetails =
      service.describe(sysmonEvtxRec, {[&sysmonFixture](const QString &, QString &) { return sysmonFixture; }});
  if (!sysmonFixtureDetails.has_value()) return 1;
  if (sysmonFixtureDetails->state == fie::domain::ArtifactParseState::Failed) return 1;
  if (sysmonFixtureDetails->evtxLogEntries.empty()) return 1;
  if (sysmonFixtureDetails->evtxLogEntries.front().events.size() < 6) return 1;

  // EVTX focused primary channel variants (System/Application) should parse without non-primary warning
  fie::domain::ArtifactRecord systemEvtxRec = evtxRec;
  systemEvtxRec.sourceLogicalPath = "/Windows/System32/winevt/Logs/System.evtx";
  const auto systemDetails = service.describe(systemEvtxRec, {[&evtxBytes](const QString &, QString &) { return evtxBytes; }});
  if (!systemDetails.has_value()) return 1;
  for (const auto &w : systemDetails->warnings) {
    if (w.contains("Non-primary EVTX channel")) return 1;
  }
  fie::domain::ArtifactRecord applicationEvtxRec = evtxRec;
  applicationEvtxRec.sourceLogicalPath = "/Windows/System32/winevt/Logs/Application.evtx";
  const auto applicationDetails =
      service.describe(applicationEvtxRec, {[&evtxBytes](const QString &, QString &) { return evtxBytes; }});
  if (!applicationDetails.has_value()) return 1;
  for (const auto &w : applicationDetails->warnings) {
    if (w.contains("Non-primary EVTX channel")) return 1;
  }
  const auto sysmonDetails = service.describe(sysmonEvtxRec, {[&evtxBytes](const QString &, QString &) { return evtxBytes; }});
  if (!sysmonDetails.has_value()) return 1;
  if (sysmonDetails->evtxLogEntries.empty()) return 1;
  if (sysmonDetails->evtxLogEntries.front().logName != "Microsoft-Windows-Sysmon/Operational.evtx") return 1;
  for (const auto &w : sysmonDetails->warnings) {
    if (w.contains("Non-primary EVTX channel")) return 1;
  }

  // EVTX truncated handling
  const QByteArray evtxShort("ElfFile", 7);
  const auto evtxFailed = service.describe(evtxRec, {[&evtxShort](const QString &, QString &) { return evtxShort; }});
  if (!evtxFailed.has_value()) return 1;
  if (evtxFailed->state != fie::domain::ArtifactParseState::Failed) return 1;

  // EVTX malformed second record trailer -> Partial with first-record salvage
  const auto evtxCorrupt = buildEvtxFixture(
      {buildEvtxRecord(100, 133876560000000000ULL,
                       buildEvtxNameRefFixturePayload("ProviderA", 1, 4, "HOST1", 0, 0, 0ULL, 133876560000000000ULL)),
       buildEvtxRecord(101, 133876560100000000ULL,
                       buildEvtxNameRefFixturePayload("ProviderB", 2, 4, "HOST1", 0, 0, 0ULL, 133876560100000000ULL),
                       true)});
  const auto evtxPartial = service.describe(evtxRec, {[&evtxCorrupt](const QString &, QString &) { return evtxCorrupt; }});
  if (!evtxPartial.has_value()) return 1;
  if (evtxPartial->state != fie::domain::ArtifactParseState::Partial) return 1;
  if (evtxPartial->evtxLogEntries.empty() || evtxPartial->evtxLogEntries.front().events.empty()) return 1;

  // EVTX malformed payload in second record -> warning + salvage first record
  QByteArray malformedPayload = QByteArray::fromHex("01020304AABBCCDD");
  const auto evtxMalformed = buildEvtxFixture(
      {buildEvtxRecord(200, 133876560000000000ULL,
                       buildEvtxNameRefFixturePayload("ProviderGood", 3, 4, "HOST1", 0, 0, 0ULL, 133876560000000000ULL)),
       buildEvtxRecord(201, 133876560100000000ULL, malformedPayload)});
  const auto evtxMalformedDetails =
      service.describe(evtxRec, {[&evtxMalformed](const QString &, QString &) { return evtxMalformed; }});
  if (!evtxMalformedDetails.has_value()) return 1;
  if (evtxMalformedDetails->state != fie::domain::ArtifactParseState::Partial) return 1;
  if (evtxMalformedDetails->warnings.isEmpty()) return 1;
  if (evtxMalformedDetails->evtxLogEntries.empty()) return 1;
  if (evtxMalformedDetails->evtxLogEntries.front().events.size() != 2) return 1;

  // EVTX invalid chunk signature -> Unsupported
  QByteArray evtxNoChunk(4096 + 65536, 0);
  evtxNoChunk.replace(0, 7, QByteArray("ElfFile", 7));
  evtxNoChunk.replace(4096, 8, QByteArray("BADCHUNK", 8));
  const auto evtxUnsupported = service.describe(evtxRec, {[&evtxNoChunk](const QString &, QString &) { return evtxNoChunk; }});
  if (!evtxUnsupported.has_value()) return 1;
  if (evtxUnsupported->state != fie::domain::ArtifactParseState::Unsupported) return 1;

  // EVTX non-primary channel should keep generic warning while still parsing
  fie::domain::ArtifactRecord nonPrimaryRec = evtxRec;
  nonPrimaryRec.sourceLogicalPath = "/Windows/System32/winevt/Logs/Setup.evtx";
  const auto nonPrimaryDetails = service.describe(nonPrimaryRec, {[&evtxBytes](const QString &, QString &) { return evtxBytes; }});
  if (!nonPrimaryDetails.has_value()) return 1;
  if (nonPrimaryDetails->evtxLogEntries.empty()) return 1;
  if (nonPrimaryDetails->evtxLogEntries.front().logName != "Setup.evtx") return 1;
  bool sawNonPrimaryWarning = false;
  for (const auto &w : nonPrimaryDetails->warnings) {
    if (w.contains("Non-primary EVTX channel")) {
      sawNonPrimaryWarning = true;
      break;
    }
  }
  if (!sawNonPrimaryWarning) return 1;

  // Unsupported type
  fie::domain::ArtifactRecord unsupported;
  unsupported.sourceLogicalPath = "/Users/Alice/NTUSER.DAT";
  if (service.describe(unsupported, {[](const QString &, QString &) { return QByteArray(); }}).has_value()) return 1;

  return 0;
}
