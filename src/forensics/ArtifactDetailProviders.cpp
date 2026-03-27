#include "ForensicImageExtractor/forensics/ArtifactDetailProviders.h"
#include "ForensicImageExtractor/forensics/ArtifactMaterializationService.h"
#include "ForensicImageExtractor/forensics/RegistryHive.h"
#include "detail_providers/EvtxBinXmlParser.h"
#include "detail_providers/SrumEsentParser.h"

#include <QStringDecoder>
#include <QMap>
#include <QRegularExpression>
#include <QXmlStreamReader>
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
  if (sec < 0) return std::nullopt;
  return QDateTime::fromSecsSinceEpoch(sec, Qt::UTC);
}

QString decodeUtf16Le(const QByteArray &bytes) {
  QStringDecoder decoder(QStringDecoder::Utf16LE);
  QString text = decoder.decode(bytes);
  const int nullPos = text.indexOf(QChar('\0'));
  if (nullPos >= 0) text = text.left(nullPos);
  return text;
}

struct DecodedTextPayload {
  QString text;
  QString encoding;
};

DecodedTextPayload decodeTextPayload(const QByteArray &bytes) {
  if (bytes.startsWith("\xEF\xBB\xBF")) {
    return {QString::fromUtf8(bytes.mid(3)), "utf-8-bom"};
  }
  if (bytes.startsWith("\xFF\xFE")) {
    QStringDecoder dec(QStringDecoder::Utf16LE);
    return {dec.decode(bytes.mid(2)), "utf-16le-bom"};
  }
  if (bytes.startsWith("\xFE\xFF")) {
    QStringDecoder dec(QStringDecoder::Utf16BE);
    return {dec.decode(bytes.mid(2)), "utf-16be-bom"};
  }

  QStringDecoder utf8(QStringDecoder::Utf8);
  const QString asUtf8 = utf8.decode(bytes);
  if (!utf8.hasError()) return {asUtf8, "utf-8"};

  if (bytes.size() % 2 == 0 && bytes.size() >= 4) {
    int oddNull = 0;
    int evenNull = 0;
    for (int i = 0; i < bytes.size(); ++i) {
      if (bytes[i] == '\0') ((i % 2) == 0 ? evenNull : oddNull)++;
    }
    const int threshold = bytes.size() / 6;
    if (oddNull > threshold && evenNull < threshold) {
      QStringDecoder dec(QStringDecoder::Utf16LE);
      return {dec.decode(bytes), "utf-16le-heuristic"};
    }
    if (evenNull > threshold && oddNull < threshold) {
      QStringDecoder dec(QStringDecoder::Utf16BE);
      return {dec.decode(bytes), "utf-16be-heuristic"};
    }
  }

  return {QString::fromLatin1(bytes), "latin1-fallback"};
}

std::optional<QDateTime> parseTrustedTimestamp(const QString &value) {
  const QString v = value.trimmed();
  if (v.isEmpty()) return std::nullopt;
  const auto iso = QDateTime::fromString(v, Qt::ISODate);
  if (iso.isValid()) return iso.toUTC();
  bool ok = false;
  const qulonglong ticks = v.toULongLong(&ok);
  if (!ok) return std::nullopt;
  return filetimeToUtc(ticks);
}

QString readNullTerminatedAnsi(const QByteArray &bytes, int off) {
  if (off < 0 || off >= bytes.size()) return {};
  int end = off;
  while (end < bytes.size() && bytes[end] != '\0') ++end;
  return QString::fromLatin1(bytes.constData() + off, end - off);
}

struct LnkSummaryFields {
  QString targetPath;
  QString workingDirectory;
  QString commandLineArguments;
  QString relativePath;
  std::optional<QDateTime> createdTimestamp;
  std::optional<QDateTime> modifiedTimestamp;
  std::optional<QDateTime> accessedTimestamp;
  QStringList warnings;
  domain::ArtifactParseState state{domain::ArtifactParseState::Partial};
  QString summary;
  QString error;
};

LnkSummaryFields parseLnkSummaryFields(const QByteArray &bytes) {
  LnkSummaryFields out;
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

QString bytesToHex(const QByteArray &bytes) {
  QString out;
  out.reserve(bytes.size() * 2);
  static const char *kHex = "0123456789abcdef";
  for (const auto ch : bytes) {
    const auto v = static_cast<quint8>(ch);
    out.push_back(QChar(kHex[(v >> 4) & 0x0F]));
    out.push_back(QChar(kHex[v & 0x0F]));
  }
  return out;
}

class JumpListAutomaticProvider final : public IArtifactDetailProvider {
  static constexpr quint32 kEndOfChain = 0xFFFFFFFEu;
  static constexpr quint32 kFreeSector = 0xFFFFFFFFu;

  struct CfbfDirectoryEntry {
    QString name;
    quint8 type{0};
    quint32 startSector{kEndOfChain};
    quint64 streamSize{0};
  };

  struct DestListLayout {
    int fixedSize{0};
    int streamNumberOffset{88};
    int timestampOffset{-1};
    int pinOffset{-1};
    int accessCountOffset{-1};
    int pathLengthOffset{-1};
    bool trustMetrics{false};
    QString label;
  };

  struct CfbfFile {
    QByteArray bytes;
    int sectorSize{0};
    int miniSectorSize{0};
    quint32 miniStreamCutoff{4096};
    std::vector<quint32> fat;
    std::vector<quint32> miniFat;
    std::vector<CfbfDirectoryEntry> directory;
    QByteArray miniStream;
  };

public:
  QString name() const override { return "windows.jump_list_v1"; }
  bool supports(const domain::ArtifactRecord &artifact) const override {
    return artifact.sourceLogicalPath.endsWith(".automaticdestinations-ms", Qt::CaseInsensitive) ||
           artifact.sourceLogicalPath.endsWith(".customdestinations-ms", Qt::CaseInsensitive);
  }
  domain::ArtifactDetails parse(const domain::ArtifactRecord &artifact,
                                const ArtifactDetailRequest &request) const override {
    domain::ArtifactDetails out;
    out.provider = name();
    out.jumpListFormat = artifact.sourceLogicalPath.endsWith(".customdestinations-ms", Qt::CaseInsensitive)
                             ? "customdestinations"
                             : "automaticdestinations";
    if (out.jumpListFormat == "customdestinations") {
      out.state = domain::ArtifactParseState::Unsupported;
      out.summary = "CustomDestinations parsing is deferred in Jump List v1";
      out.warnings.push_back("Only AutomaticDestinations are supported in this pass");
      return out;
    }

    QString error;
    const auto bytes = request.readBytes(artifact.sourceLogicalPath, error);
    if (!error.isEmpty()) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = error;
      out.summary = "Unable to read Jump List payload";
      return out;
    }

    CfbfFile cfbf;
    if (!openCfbf(bytes, cfbf, error)) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = error;
      out.summary = "AutomaticDestinations parse failed";
      return out;
    }

    QByteArray destListBytes;
    bool sawDestList = false;
    for (const auto &entry : cfbf.directory) {
      if (entry.type != 2) continue;
      if (entry.name.compare("DestList", Qt::CaseInsensitive) == 0) {
        sawDestList = true;
        if (!readStream(cfbf, entry.startSector, entry.streamSize, destListBytes, error)) {
          out.state = domain::ArtifactParseState::Failed;
          out.error = error;
          out.summary = "AutomaticDestinations DestList stream read failed";
          return out;
        }
        break;
      }
    }
    if (!sawDestList) {
      out.state = domain::ArtifactParseState::Partial;
      out.summary = "DestList stream is not present";
      out.warnings.push_back("AutomaticDestinations file has no DestList stream");
      return out;
    }

    std::vector<CfbfDirectoryEntry> lnkStreams;
    for (const auto &entry : cfbf.directory) {
      if (entry.type != 2) continue;
      if (entry.name.compare("DestList", Qt::CaseInsensitive) == 0) continue;
      lnkStreams.push_back(entry);
    }

    if (destListBytes.size() < 32) {
      out.state = domain::ArtifactParseState::Partial;
      out.summary = "DestList stream is too short";
      out.warnings.push_back("DestList header is truncated");
      return out;
    }

    out.jumpListVersion = static_cast<int>(readLe32(destListBytes, 0));
    out.jumpListReportedEntryCount = readLe32(destListBytes, 4);

    int offset = 32;
    bool truncated = false;
    bool trustLimitedLayoutUsed = false;
    while (offset + 114 <= destListBytes.size()) {
      quint16 pathChars = 0;
      const auto layout = detectLayout(destListBytes, offset, pathChars);
      if (!layout.has_value()) {
        truncated = true;
        break;
      }
      if (!layout->trustMetrics) trustLimitedLayoutUsed = true;

      domain::ArtifactDetails::JumpListEntry e;
      e.entryIdentifier = bytesToHex(destListBytes.mid(offset, 8));
      const quint32 streamNo = readLe32(destListBytes, offset + layout->streamNumberOffset);
      if (streamNo != 0 && streamNo != kFreeSector) e.streamNumber = streamNo;
      if (layout->trustMetrics) {
        e.lastAccessTimestamp = filetimeToUtc(readLe64(destListBytes, offset + layout->timestampOffset));
        const quint32 pinRaw = readLe32(destListBytes, offset + layout->pinOffset);
        if (pinRaw == 0) {
          e.pinned = false;
        } else if (pinRaw == 1) {
          e.pinned = true;
        } else if (pinRaw != kFreeSector) {
          out.warnings.push_back(QString("Unrecognized Jump List pin state for entry %1").arg(e.entryIdentifier));
        }
        const quint32 count = readLe32(destListBytes, offset + layout->accessCountOffset);
        if (count > 0) e.accessCount = count;
      }
      if (pathChars > 0) {
        e.targetPath = decodeUtf16Le(destListBytes.mid(offset + layout->fixedSize, static_cast<int>(pathChars) * 2)).trimmed();
      }

      if (e.streamNumber.has_value()) {
        const auto linked = findLinkedLnkStream(lnkStreams, *e.streamNumber);
        if (linked.has_value()) {
          QString linkedError;
          QByteArray linkedBytes;
          if (readStream(cfbf, linked->startSector, linked->streamSize, linkedBytes, linkedError)) {
            const auto linkedSummary = parseLnkSummaryFields(linkedBytes);
            for (const auto &w : linkedSummary.warnings) {
              out.warnings.push_back(QString("Linked LNK stream %1: %2").arg(linked->name, w));
            }
            if (!linkedSummary.targetPath.isEmpty() && e.targetPath.isEmpty()) {
              e.targetPath = linkedSummary.targetPath;
            }
            if (e.targetSummary.isEmpty()) {
              if (!linkedSummary.relativePath.isEmpty()) {
                e.targetSummary = QString("LNK relative path: %1").arg(linkedSummary.relativePath);
              } else if (!linkedSummary.workingDirectory.isEmpty()) {
                e.targetSummary = QString("LNK working dir: %1").arg(linkedSummary.workingDirectory);
              } else if (!linkedSummary.commandLineArguments.isEmpty()) {
                e.targetSummary = QString("LNK args: %1").arg(linkedSummary.commandLineArguments);
              } else {
                e.targetSummary = QString("LNK stream parsed: %1").arg(linked->name);
              }
            }
          } else {
            out.warnings.push_back(QString("Linked LNK stream %1 could not be read: %2").arg(linked->name, linkedError));
          }
        } else {
          out.warnings.push_back(QString("Linked LNK stream %1 was not found").arg(*e.streamNumber));
        }
      }
      if (e.targetPath.isEmpty() && e.targetSummary.isEmpty()) e.targetSummary = "Target path unavailable";
      out.jumpListEntries.push_back(std::move(e));
      offset += layout->fixedSize + (static_cast<int>(pathChars) * 2);
    }

    if (truncated) out.warnings.push_back("DestList entries truncated");
    if (trustLimitedLayoutUsed) {
      out.warnings.push_back("Jump List trust-limited layout encountered; timestamp/pin/access_count left null");
    }
    if (out.jumpListEntries.empty()) {
      out.state = domain::ArtifactParseState::Partial;
      out.summary = "DestList parsed with no conservative entries";
      return out;
    }
    out.state = out.warnings.isEmpty() ? domain::ArtifactParseState::Parsed : domain::ArtifactParseState::Partial;
    out.summary = "AutomaticDestinations DestList parsed";
    return out;
  }

private:
  static bool readSector(const QByteArray &bytes, quint32 sectorId, int sectorSize, QByteArray &out, QString &error) {
    const qint64 start = static_cast<qint64>(sectorId + 1) * sectorSize;
    if (sectorId == kEndOfChain || sectorId == kFreeSector || start < 0 ||
        start + sectorSize > static_cast<qint64>(bytes.size())) {
      error = "CFBF sector offset is out of range";
      return false;
    }
    out = bytes.mid(static_cast<int>(start), sectorSize);
    return true;
  }

  static std::optional<DestListLayout> detectLayout(const QByteArray &destListBytes, int offset, quint16 &pathChars) {
    for (const DestListLayout &candidate : {
             DestListLayout{114, 88, 100, 104, 108, 112, true, "v1-114"},
             DestListLayout{128, 88, -1, -1, -1, 126, false, "v2-128"},
         }) {
      if (offset + candidate.fixedSize > destListBytes.size()) continue;
      bool ok = false;
      const auto chars = readLe16(destListBytes, offset + candidate.pathLengthOffset, &ok);
      if (!ok) continue;
      const int pathBytes = static_cast<int>(chars) * 2;
      if (chars <= 8192 && offset + candidate.fixedSize + pathBytes <= destListBytes.size()) {
        pathChars = chars;
        return candidate;
      }
    }
    return std::nullopt;
  }

  static std::optional<CfbfDirectoryEntry> findLinkedLnkStream(const std::vector<CfbfDirectoryEntry> &streams,
                                                               quint32 streamNumber) {
    const QString hexLabel = QString::number(streamNumber, 16);
    const QString decimalLabel = QString::number(streamNumber);
    const QString paddedHex = QString("%1").arg(hexLabel, 8, QChar('0'));
    for (const auto &entry : streams) {
      if (entry.name.compare(hexLabel, Qt::CaseInsensitive) == 0 ||
          entry.name.compare(decimalLabel, Qt::CaseInsensitive) == 0 ||
          entry.name.compare(paddedHex, Qt::CaseInsensitive) == 0) {
        return entry;
      }
    }
    return std::nullopt;
  }

  static bool readFatChain(const QByteArray &bytes, const std::vector<quint32> &fat, quint32 startSector,
                           int sectorSize, QByteArray &out, QString &error) {
    out.clear();
    if (startSector == kEndOfChain || startSector == kFreeSector) return true;
    std::vector<bool> seen(fat.size(), false);
    quint32 current = startSector;
    while (current != kEndOfChain) {
      if (current >= fat.size()) {
        error = "CFBF FAT chain points outside FAT table";
        return false;
      }
      if (seen[current]) {
        error = "CFBF FAT chain loop detected";
        return false;
      }
      seen[current] = true;
      QByteArray sector;
      if (!readSector(bytes, current, sectorSize, sector, error)) return false;
      out += sector;
      current = fat[current];
    }
    return true;
  }

  static bool openCfbf(const QByteArray &bytes, CfbfFile &out, QString &error) {
    if (bytes.size() < 512) {
      error = "Input too short for CFBF header";
      return false;
    }
    if (bytes.mid(0, 8) != QByteArray::fromHex("D0CF11E0A1B11AE1")) {
      error = "Missing CFBF signature";
      return false;
    }
    const quint16 sectorShift = readLe16(bytes, 30);
    const quint16 miniShift = readLe16(bytes, 32);
    out.sectorSize = 1 << sectorShift;
    out.miniSectorSize = 1 << miniShift;
    if (out.sectorSize < 512 || out.miniSectorSize <= 0 || out.miniSectorSize > out.sectorSize) {
      error = "Unsupported CFBF sector sizing";
      return false;
    }

    const quint32 numFatSectors = readLe32(bytes, 44);
    const quint32 firstDirSector = readLe32(bytes, 48);
    out.miniStreamCutoff = readLe32(bytes, 56);
    const quint32 firstMiniFatSector = readLe32(bytes, 60);
    const quint32 numMiniFatSectors = readLe32(bytes, 64);
    quint32 firstDifatSector = readLe32(bytes, 68);
    const quint32 numDifatSectors = readLe32(bytes, 72);

    std::vector<quint32> fatSectorIds;
    fatSectorIds.reserve(numFatSectors);
    for (int i = 0; i < 109; ++i) {
      const quint32 sid = readLe32(bytes, 76 + (i * 4));
      if (sid != kFreeSector) fatSectorIds.push_back(sid);
    }
    for (quint32 i = 0; i < numDifatSectors; ++i) {
      if (firstDifatSector == kEndOfChain || firstDifatSector == kFreeSector) break;
      QByteArray sector;
      if (!readSector(bytes, firstDifatSector, out.sectorSize, sector, error)) return false;
      const int entryCount = (out.sectorSize / 4) - 1;
      for (int e = 0; e < entryCount; ++e) {
        const quint32 sid = readLe32(sector, e * 4);
        if (sid != kFreeSector) fatSectorIds.push_back(sid);
      }
      firstDifatSector = readLe32(sector, out.sectorSize - 4);
    }
    if (fatSectorIds.size() < numFatSectors) {
      error = "CFBF DIFAT does not list enough FAT sectors";
      return false;
    }
    if (fatSectorIds.size() > numFatSectors) fatSectorIds.resize(numFatSectors);

    for (const auto sid : fatSectorIds) {
      QByteArray sector;
      if (!readSector(bytes, sid, out.sectorSize, sector, error)) return false;
      for (int i = 0; i < out.sectorSize; i += 4) out.fat.push_back(readLe32(sector, i));
    }
    if (out.fat.empty()) {
      error = "CFBF FAT is empty";
      return false;
    }

    QByteArray dirBytes;
    if (!readFatChain(bytes, out.fat, firstDirSector, out.sectorSize, dirBytes, error)) return false;
    for (int off = 0; off + 128 <= dirBytes.size(); off += 128) {
      CfbfDirectoryEntry e;
      const int nameLen = readLe16(dirBytes, off + 64);
      if (nameLen >= 2 && nameLen <= 64) {
        e.name = decodeUtf16Le(dirBytes.mid(off, nameLen - 2));
      }
      e.type = static_cast<quint8>(dirBytes[off + 66]);
      e.startSector = readLe32(dirBytes, off + 116);
      e.streamSize = readLe64(dirBytes, off + 120);
      out.directory.push_back(std::move(e));
    }

    if (numMiniFatSectors > 0 && firstMiniFatSector != kEndOfChain && firstMiniFatSector != kFreeSector) {
      QByteArray miniFatBytes;
      if (!readFatChain(bytes, out.fat, firstMiniFatSector, out.sectorSize, miniFatBytes, error)) return false;
      const int maxBytes = static_cast<int>(numMiniFatSectors) * out.sectorSize;
      miniFatBytes.truncate(std::min(maxBytes, miniFatBytes.size()));
      for (int i = 0; i + 4 <= miniFatBytes.size(); i += 4) out.miniFat.push_back(readLe32(miniFatBytes, i));
    }

    for (const auto &entry : out.directory) {
      if (entry.type != 5) continue;
      QByteArray rootMiniStream;
      if (!readFatChain(bytes, out.fat, entry.startSector, out.sectorSize, rootMiniStream, error)) return false;
      if (entry.streamSize < static_cast<quint64>(rootMiniStream.size())) {
        rootMiniStream.truncate(static_cast<int>(entry.streamSize));
      }
      out.miniStream = std::move(rootMiniStream);
      break;
    }

    out.bytes = bytes;
    return true;
  }

  static bool readStream(const CfbfFile &cfbf, quint32 startSector, quint64 streamSize, QByteArray &out, QString &error) {
    out.clear();
    if (streamSize == 0 || startSector == kEndOfChain || startSector == kFreeSector) return true;

    if (streamSize >= cfbf.miniStreamCutoff || cfbf.miniFat.empty() || cfbf.miniStream.isEmpty()) {
      QByteArray data;
      if (!readFatChain(cfbf.bytes, cfbf.fat, startSector, cfbf.sectorSize, data, error)) return false;
      if (streamSize < static_cast<quint64>(data.size())) data.truncate(static_cast<int>(streamSize));
      out = std::move(data);
      return true;
    }

    std::vector<bool> seen(cfbf.miniFat.size(), false);
    quint32 current = startSector;
    while (current != kEndOfChain) {
      if (current >= cfbf.miniFat.size()) {
        error = "CFBF mini stream chain points outside MiniFAT table";
        return false;
      }
      if (seen[current]) {
        error = "CFBF mini stream chain loop detected";
        return false;
      }
      seen[current] = true;
      const qint64 off = static_cast<qint64>(current) * cfbf.miniSectorSize;
      if (off < 0 || off + cfbf.miniSectorSize > cfbf.miniStream.size()) {
        error = "CFBF mini stream sector offset is out of range";
        return false;
      }
      out += cfbf.miniStream.mid(static_cast<int>(off), cfbf.miniSectorSize);
      current = cfbf.miniFat[current];
    }
    if (streamSize < static_cast<quint64>(out.size())) out.truncate(static_cast<int>(streamSize));
    return true;
  }
};

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

std::vector<QString> extractConservativeUtf16Paths(const QByteArray &raw, QStringList &warnings) {
  if ((raw.size() % 2) != 0) warnings.push_back("AppCompatCache binary has an odd byte length; trailing byte ignored");
  const int usableSize = raw.size() - (raw.size() % 2);
  QStringDecoder decoder(QStringDecoder::Utf16LE);
  const QString text = decoder.decode(raw.left(usableSize));
  const auto lines = text.split(QChar('\0'), Qt::SkipEmptyParts);

  std::vector<QString> out;
  for (const auto &token : lines) {
    const QString t = token.trimmed();
    if (t.size() < 4) continue;
    const bool drive = t.size() >= 3 && t[1] == ':' && t[2] == '\\' &&
                       ((t[0] >= 'A' && t[0] <= 'Z') || (t[0] >= 'a' && t[0] <= 'z'));
    const bool ntDevice = t.startsWith("\\Device\\", Qt::CaseInsensitive) || t.startsWith("\\??\\", Qt::CaseInsensitive) ||
                          t.startsWith("\\\\", Qt::CaseInsensitive);
    if (!drive && !ntDevice) continue;
    if (t.indexOf('\\') < 0) continue;
    out.push_back(t);
  }

  std::stable_sort(out.begin(), out.end(), [](const auto &a, const auto &b) {
    return a.compare(b, Qt::CaseInsensitive) < 0;
  });
  out.erase(std::unique(out.begin(), out.end(), [](const auto &a, const auto &b) {
              return a.compare(b, Qt::CaseInsensitive) == 0;
            }),
            out.end());
  return out;
}

QStringList decodeRegistryMultiSz(const RegistryHive::Value &value) {
  QStringList out;
  if (value.rawData.isEmpty()) return out;
  QByteArray raw = value.rawData;
  if ((raw.size() % 2) != 0) raw.chop(1);
  QStringDecoder decoder(QStringDecoder::Utf16LE);
  const auto text = decoder.decode(raw);
  const auto parts = text.split(QChar('\0'), Qt::SkipEmptyParts);
  for (const auto &part : parts) {
    const auto t = part.trimmed();
    if (!t.isEmpty()) out.push_back(t);
  }
  out.removeDuplicates();
  return out;
}

void parseUsbStorIdentifier(const QString &deviceIdentifier,
                            QString &vendor,
                            QString &product,
                            QString &revision) {
  const auto parts = deviceIdentifier.split('&', Qt::SkipEmptyParts);
  for (const auto &part : parts) {
    if (part.startsWith("Ven_", Qt::CaseInsensitive)) vendor = part.mid(4);
    else if (part.startsWith("Prod_", Qt::CaseInsensitive)) product = part.mid(5);
    else if (part.startsWith("Rev_", Qt::CaseInsensitive)) revision = part.mid(4);
  }
}

class AppCompatCacheProvider final : public IArtifactDetailProvider {
public:
  QString name() const override { return "windows.appcompatcache_v1"; }
  bool supports(const domain::ArtifactRecord &artifact) const override {
    return artifact.artifactName.compare("AppCompatCache resolver", Qt::CaseInsensitive) == 0 &&
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
      out.summary = "AppCompatCache parse failed";
      return out;
    }

    const QString controlSet = resolveControlSetPathPrefix(hive, out.warnings);
    const QString keyPath = QString("%1\\Control\\Session Manager\\AppCompatCache").arg(controlSet);
    const auto key = hive.keyByPath(keyPath, error);
    if (!key.has_value()) {
      out.state = out.warnings.isEmpty() ? domain::ArtifactParseState::Unsupported : domain::ArtifactParseState::Partial;
      out.summary = "AppCompatCache key is not present";
      return out;
    }
    const auto *cacheValue = findValueCi(*key, "AppCompatCache");
    if (!cacheValue) {
      out.state = domain::ArtifactParseState::Unsupported;
      out.summary = "AppCompatCache value is not present";
      return out;
    }
    if (cacheValue->rawData.isEmpty()) {
      out.state = domain::ArtifactParseState::Partial;
      out.summary = "AppCompatCache value is empty";
      return out;
    }
    if (cacheValue->type != 3) {
      out.warnings.push_back(QString("Unexpected AppCompatCache value type: %1").arg(cacheValue->type));
    }

    const auto paths = extractConservativeUtf16Paths(cacheValue->rawData, out.warnings);
    out.appCompatCacheFormat = "utf16_path_scan_v1";
    for (int i = 0; i < static_cast<int>(paths.size()); ++i) {
      domain::ArtifactDetails::AppCompatCacheEntry e;
      e.sourceRegistryPath = keyPath + "\\AppCompatCache";
      e.entryIndex = i;
      e.executablePath = paths[i];
      out.appCompatCacheEntries.push_back(std::move(e));
    }

    if (out.appCompatCacheEntries.empty()) {
      out.state = out.warnings.isEmpty() ? domain::ArtifactParseState::Unsupported : domain::ArtifactParseState::Partial;
      out.summary = out.warnings.isEmpty() ? "AppCompatCache format is unsupported in v1"
                                           : "AppCompatCache parsed with no conservative paths";
      return out;
    }

    out.state = out.warnings.isEmpty() ? domain::ArtifactParseState::Parsed : domain::ArtifactParseState::Partial;
    out.summary = "AppCompatCache path entries parsed (execution/timestamp not inferred in v1)";
    return out;
  }
};

class ServicesProvider final : public IArtifactDetailProvider {
public:
  QString name() const override { return "windows.services_v1"; }
  bool supports(const domain::ArtifactRecord &artifact) const override {
    return artifact.artifactName.compare("Services hive resolver", Qt::CaseInsensitive) == 0 &&
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
      out.summary = "Services parse failed";
      return out;
    }

    const QString controlSet = resolveControlSetPathPrefix(hive, out.warnings);
    const QString servicesPath = QString("%1\\Services").arg(controlSet);
    const auto services = hive.childKeys(servicesPath, error);
    if (!error.isEmpty() || services.empty()) {
      out.state = out.warnings.isEmpty() ? domain::ArtifactParseState::Unsupported : domain::ArtifactParseState::Partial;
      out.summary = "Services key is not present";
      return out;
    }

    for (const auto &serviceKey : services) {
      domain::ArtifactDetails::ServiceEntry e;
      e.serviceName = serviceKey.path.section('\\', -1);
      e.sourceRegistryPath = serviceKey.path;
      e.keyLastWriteTimestamp = serviceKey.lastWrite;

      if (const auto *v = findValueCi(serviceKey, "DisplayName")) e.displayName = decodeRegistryString(*v);
      if (const auto *v = findValueCi(serviceKey, "ImagePath")) e.imagePath = decodeRegistryString(*v);
      if (const auto *v = findValueCi(serviceKey, "ObjectName")) e.objectName = decodeRegistryString(*v);
      if (const auto *v = findValueCi(serviceKey, "Description")) e.description = decodeRegistryString(*v);
      if (const auto *v = findValueCi(serviceKey, "LoadOrderGroup")) e.loadOrderGroup = decodeRegistryString(*v);
      if (const auto *v = findValueCi(serviceKey, "Start")) e.startType = decodeRegistryDword(*v);
      if (const auto *v = findValueCi(serviceKey, "Type")) e.serviceType = decodeRegistryDword(*v);
      if (const auto *v = findValueCi(serviceKey, "DelayedAutostart")) {
        const auto d = decodeRegistryDword(*v);
        if (d.has_value()) e.delayedAutoStart = (*d != 0);
      }

      if (const auto *v = findValueCi(serviceKey, "DependOnService")) {
        for (const auto &dep : decodeRegistryMultiSz(*v)) e.dependencies.push_back(QString("service:%1").arg(dep));
      }
      if (const auto *v = findValueCi(serviceKey, "DependOnGroup")) {
        for (const auto &dep : decodeRegistryMultiSz(*v)) e.dependencies.push_back(QString("group:%1").arg(dep));
      }

      const auto params = hive.keyByPath(serviceKey.path + "\\Parameters", error);
      if (params.has_value()) {
        if (const auto *v = findValueCi(*params, "ServiceDll")) e.serviceDll = decodeRegistryString(*v);
      } else {
        error.clear();
      }

      out.serviceEntries.push_back(std::move(e));
    }

    std::stable_sort(out.serviceEntries.begin(), out.serviceEntries.end(), [](const auto &a, const auto &b) {
      return a.serviceName.compare(b.serviceName, Qt::CaseInsensitive) < 0;
    });
    out.state = out.warnings.isEmpty() ? domain::ArtifactParseState::Parsed : domain::ArtifactParseState::Partial;
    out.summary = "Service configuration entries parsed";
    return out;
  }
};

class UsbRegistryProvider final : public IArtifactDetailProvider {
public:
  QString name() const override { return "windows.usb_registry_v1"; }
  bool supports(const domain::ArtifactRecord &artifact) const override {
    return artifact.artifactName.compare("USB registry resolver", Qt::CaseInsensitive) == 0 &&
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
      out.summary = "USB registry parse failed";
      return out;
    }

    const QString controlSet = resolveControlSetPathPrefix(hive, out.warnings);
    const QString usbstorPath = QString("%1\\Enum\\USBSTOR").arg(controlSet);
    const auto deviceKeys = hive.childKeys(usbstorPath, error);
    if (!error.isEmpty() || deviceKeys.empty()) {
      out.state = out.warnings.isEmpty() ? domain::ArtifactParseState::Unsupported : domain::ArtifactParseState::Partial;
      out.summary = "USBSTOR key is not present";
      return out;
    }

    for (const auto &deviceKey : deviceKeys) {
      const QString deviceIdentifier = deviceKey.path.section('\\', -1);
      const auto instanceKeys = hive.childKeys(deviceKey.path, error);
      if (!error.isEmpty()) {
        error.clear();
        continue;
      }
      for (const auto &instanceKey : instanceKeys) {
        domain::ArtifactDetails::UsbDeviceEntry e;
        e.deviceClass = "USBSTOR";
        e.enumRoot = "Enum\\USBSTOR";
        e.deviceIdentifier = deviceIdentifier;
        e.instanceId = instanceKey.path.section('\\', -1);
        e.serialNumber = e.instanceId.section('&', 0, 0);
        parseUsbStorIdentifier(deviceIdentifier, e.vendor, e.product, e.revision);
        e.keyLastWriteTimestamp = instanceKey.lastWrite;
        e.sourceRegistryPath = instanceKey.path;

        if (const auto *v = findValueCi(instanceKey, "FriendlyName")) e.friendlyName = decodeRegistryString(*v);
        if (const auto *v = findValueCi(instanceKey, "ParentIdPrefix")) e.parentIdPrefix = decodeRegistryString(*v);
        if (const auto *v = findValueCi(instanceKey, "Service")) e.service = decodeRegistryString(*v);
        if (const auto *v = findValueCi(instanceKey, "ClassGUID")) e.classGuid = decodeRegistryString(*v);

        const bool anyField = !e.deviceIdentifier.isEmpty() || !e.instanceId.isEmpty() || !e.vendor.isEmpty() ||
                              !e.product.isEmpty() || !e.revision.isEmpty() || !e.serialNumber.isEmpty() ||
                              !e.friendlyName.isEmpty() || !e.parentIdPrefix.isEmpty() || !e.service.isEmpty() ||
                              !e.classGuid.isEmpty() || e.keyLastWriteTimestamp.has_value();
        if (anyField) out.usbDeviceEntries.push_back(std::move(e));
      }
    }

    std::stable_sort(out.usbDeviceEntries.begin(), out.usbDeviceEntries.end(), [](const auto &a, const auto &b) {
      if (a.keyLastWriteTimestamp.has_value() != b.keyLastWriteTimestamp.has_value()) {
        return a.keyLastWriteTimestamp.has_value();
      }
      if (a.keyLastWriteTimestamp && b.keyLastWriteTimestamp &&
          a.keyLastWriteTimestamp.value() != b.keyLastWriteTimestamp.value()) {
        return a.keyLastWriteTimestamp.value() < b.keyLastWriteTimestamp.value();
      }
      if (a.deviceIdentifier.compare(b.deviceIdentifier, Qt::CaseInsensitive) != 0) {
        return a.deviceIdentifier.compare(b.deviceIdentifier, Qt::CaseInsensitive) < 0;
      }
      return a.instanceId.compare(b.instanceId, Qt::CaseInsensitive) < 0;
    });

    out.state = out.usbDeviceEntries.empty()
                    ? (out.warnings.isEmpty() ? domain::ArtifactParseState::Unsupported : domain::ArtifactParseState::Partial)
                    : (out.warnings.isEmpty() ? domain::ArtifactParseState::Parsed : domain::ArtifactParseState::Partial);
    out.summary = out.usbDeviceEntries.empty() ? "USBSTOR has no conservative entries" : "USB registry entries parsed";
    return out;
  }
};

std::optional<bool> parseXmlBool(const QString &value) {
  if (value.compare("true", Qt::CaseInsensitive) == 0 || value == "1") return true;
  if (value.compare("false", Qt::CaseInsensitive) == 0 || value == "0") return false;
  return std::nullopt;
}

class ScheduledTaskProvider final : public IArtifactDetailProvider {
public:
  QString name() const override { return "windows.scheduled_task_v1"; }
  bool supports(const domain::ArtifactRecord &artifact) const override {
    return artifact.artifactName.compare("Scheduled Task definitions", Qt::CaseInsensitive) == 0 &&
           artifact.sourceLogicalPath.startsWith("/Windows/System32/Tasks/", Qt::CaseInsensitive);
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
      out.summary = "Unable to read Scheduled Task payload";
      return out;
    }
    if (bytes.isEmpty()) {
      out.state = domain::ArtifactParseState::Partial;
      out.summary = "Scheduled Task file is empty";
      return out;
    }

    const auto decoded = decodeTextPayload(bytes);
    const QString payloadHead = decoded.text.left(256);
    if (!payloadHead.contains("<Task", Qt::CaseInsensitive) && !payloadHead.contains("<?xml", Qt::CaseInsensitive)) {
      out.state = domain::ArtifactParseState::Unsupported;
      out.summary = "Non-XML task format is unsupported in v1";
      return out;
    }

    domain::ArtifactDetails::ScheduledTaskEntry task;
    task.taskPath = artifact.sourceLogicalPath;
    task.taskName = artifact.sourceLogicalPath.section('/', -1);
    struct TriggerScratch {
      QString type;
      QString startBoundary;
      std::optional<bool> enabled;
    };
    std::optional<TriggerScratch> currentTrigger;
    QString repetitionInterval;
    QString repetitionDuration;

    QXmlStreamReader xr;
    xr.addData(bytes);
    QStringList stack;
    while (!xr.atEnd()) {
      const auto token = xr.readNext();
      if (token == QXmlStreamReader::StartElement) {
        const QString name = xr.name().toString();
        stack.push_back(name);
        if (stack.size() >= 2 && stack[stack.size() - 2] == "Triggers") {
          currentTrigger = TriggerScratch{.type = name, .startBoundary = {}, .enabled = std::nullopt};
        }
      } else if (token == QXmlStreamReader::Characters && !xr.isWhitespace()) {
        const QString value = xr.text().toString().trimmed();
        if (value.isEmpty()) continue;
        const QString path = stack.join('/');
        if (path.endsWith("RegistrationInfo/URI")) task.uri = value;
        else if (path.endsWith("RegistrationInfo/Author")) task.author = value;
        else if (path.endsWith("RegistrationInfo/Description")) task.description = value;
        else if (path.endsWith("RegistrationInfo/Date")) {
          const auto dt = QDateTime::fromString(value, Qt::ISODate);
          if (dt.isValid()) task.registrationDate = dt.toUTC();
        } else if (path.endsWith("Actions/Exec/Command")) task.command = value;
        else if (path.endsWith("Actions/Exec/Arguments")) task.arguments = value;
        else if (path.endsWith("Actions/Exec/WorkingDirectory")) task.workingDirectory = value;
        else if (path.endsWith("Settings/Enabled")) task.enabled = parseXmlBool(value);
        else if (path.endsWith("Settings/Hidden")) task.hidden = parseXmlBool(value);
        else if (path.endsWith("Principals/Principal/RunLevel")) task.runLevel = value;
        else if (path.endsWith("Principals/Principal/UserId")) task.userId = value;
        else if (path.endsWith("Principals/Principal/LogonType")) task.logonType = value;
        else if (path.endsWith("/StartBoundary") && currentTrigger.has_value()) {
          currentTrigger->startBoundary = value;
        } else if (path.endsWith("/Enabled") && currentTrigger.has_value()) {
          currentTrigger->enabled = parseXmlBool(value);
        } else if (path.endsWith("Repetition/Interval")) {
          repetitionInterval = value;
        } else if (path.endsWith("Repetition/Duration")) {
          repetitionDuration = value;
        }
      } else if (token == QXmlStreamReader::EndElement) {
        const QString name = xr.name().toString();
        if (currentTrigger.has_value() && currentTrigger->type == name) {
          QString summary = currentTrigger->type;
          if (!currentTrigger->startBoundary.isEmpty()) summary += QString(" start=%1").arg(currentTrigger->startBoundary);
          if (currentTrigger->enabled.has_value()) summary += QString(" enabled=%1").arg(*currentTrigger->enabled ? "true" : "false");
          task.triggerSummaries.push_back(summary);
          currentTrigger = std::nullopt;
        }
        if (!stack.isEmpty()) stack.pop_back();
      }
    }

    if (xr.hasError()) {
      out.state = domain::ArtifactParseState::Failed;
      out.summary = "Scheduled Task XML parse failed";
      out.error = xr.errorString();
      return out;
    }

    if (!task.command.isEmpty()) task.actionType = "Exec";
    if (!repetitionInterval.isEmpty() || !repetitionDuration.isEmpty()) {
      QStringList parts;
      if (!repetitionInterval.isEmpty()) parts.push_back(QString("interval=%1").arg(repetitionInterval));
      if (!repetitionDuration.isEmpty()) parts.push_back(QString("duration=%1").arg(repetitionDuration));
      task.repetitionSummary = parts.join(", ");
    }

    const bool anyField = !task.uri.isEmpty() || !task.author.isEmpty() || !task.description.isEmpty() || !task.command.isEmpty() ||
                          !task.arguments.isEmpty() || !task.workingDirectory.isEmpty() || task.enabled.has_value() ||
                          task.hidden.has_value() || !task.runLevel.isEmpty() || !task.userId.isEmpty() ||
                          !task.logonType.isEmpty() || !task.triggerSummaries.empty() || !task.repetitionSummary.isEmpty() ||
                          !task.actionType.isEmpty() || task.registrationDate.has_value();
    out.scheduledTaskEntries.push_back(std::move(task));
    out.state = anyField ? domain::ArtifactParseState::Parsed : domain::ArtifactParseState::Partial;
    out.summary = anyField ? "Scheduled Task XML parsed" : "Scheduled Task XML parsed with limited fields";
    if (!anyField) out.warnings.push_back("No conservative Scheduled Task fields were available");
    return out;
  }
};

class WerProvider final : public IArtifactDetailProvider {
public:
  QString name() const override { return "windows.wer_v1"; }
  bool supports(const domain::ArtifactRecord &artifact) const override {
    if (artifact.artifactName.compare("WER report files", Qt::CaseInsensitive) != 0) return false;
    if (!artifact.sourceLogicalPath.startsWith("/ProgramData/Microsoft/Windows/WER/", Qt::CaseInsensitive)) return false;
    return artifact.sourceLogicalPath.endsWith(".wer", Qt::CaseInsensitive) ||
           artifact.sourceLogicalPath.endsWith("/Report.wer", Qt::CaseInsensitive);
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
      out.summary = "Unable to read WER payload";
      return out;
    }
    if (bytes.isEmpty()) {
      out.state = domain::ArtifactParseState::Partial;
      out.summary = "WER report file is empty";
      return out;
    }

    const auto decoded = decodeTextPayload(bytes);
    const QString text = decoded.text;
    if (!text.contains('=')) {
      out.state = domain::ArtifactParseState::Unsupported;
      out.summary = "WER subformat is unsupported in v1";
      return out;
    }

    QMap<QString, QString> kv;
    QStringList problemSigs;
    const auto lines = text.split(QRegularExpression("[\r\n]+"), Qt::SkipEmptyParts);
    for (const auto &rawLine : lines) {
      const QString line = rawLine.trimmed();
      if (line.isEmpty() || line.startsWith(';') || line.startsWith('#') || line.startsWith('[')) continue;
      const int eq = line.indexOf('=');
      if (eq <= 0) continue;
      const QString key = line.left(eq).trimmed();
      const QString val = line.mid(eq + 1).trimmed();
      if (key.isEmpty()) continue;
      if (!kv.contains(key.toLower())) kv.insert(key.toLower(), val);
      if (key.startsWith("Sig[", Qt::CaseInsensitive) ||
          key.startsWith("DynamicSig[", Qt::CaseInsensitive)) {
        problemSigs.push_back(QString("%1=%2").arg(key, val));
      }
    }

    domain::ArtifactDetails::WerReportEntry report;
    report.reportPath = artifact.sourceLogicalPath;
    report.reportName = artifact.sourceLogicalPath.section('/', -1);
    report.eventType = kv.value("eventtype");
    report.applicationName = kv.value("appname");
    report.applicationPath = kv.value("apppath");
    report.faultModuleName = kv.value("modname");
    report.faultModulePath = kv.value("modpath");
    report.exceptionCode = kv.value("exceptioncode");
    report.bucketId = kv.value("bucket");
    if (report.bucketId.isEmpty()) report.bucketId = kv.value("bucketid");
    report.cabId = kv.value("cab id");
    if (report.cabId.isEmpty()) report.cabId = kv.value("cabid");
    report.reportId = kv.value("reportidentifier");
    if (report.reportId.isEmpty()) report.reportId = kv.value("reportid");
    report.response = kv.value("response");
    report.problemSignatures = problemSigs;
    report.reportTimestamp = parseTrustedTimestamp(kv.value("eventtime"));
    if (!report.reportTimestamp.has_value()) report.reportTimestamp = parseTrustedTimestamp(kv.value("reporttime"));

    const bool anyField = !report.eventType.isEmpty() || !report.applicationName.isEmpty() ||
                          !report.applicationPath.isEmpty() || !report.faultModuleName.isEmpty() ||
                          !report.faultModulePath.isEmpty() || !report.exceptionCode.isEmpty() ||
                          !report.bucketId.isEmpty() || !report.cabId.isEmpty() || !report.reportId.isEmpty() ||
                          !report.response.isEmpty() || !report.problemSignatures.isEmpty() ||
                          report.reportTimestamp.has_value();
    out.werReportEntries.push_back(std::move(report));
    out.state = anyField ? domain::ArtifactParseState::Parsed : domain::ArtifactParseState::Partial;
    out.summary = anyField ? "WER report parsed" : "WER report parsed with limited fields";
    if (!anyField) out.warnings.push_back("No conservative WER fields were available");
    if (decoded.encoding.contains("fallback")) {
      out.warnings.push_back("WER payload decoded with fallback charset");
      if (out.state == domain::ArtifactParseState::Parsed) out.state = domain::ArtifactParseState::Partial;
    }
    return out;
  }
};

class EvtxProvider final : public IArtifactDetailProvider {
public:
  QString name() const override { return "windows.evtx_v1"; }
  bool supports(const domain::ArtifactRecord &artifact) const override {
    return artifact.artifactName.compare("EVTX files", Qt::CaseInsensitive) == 0 &&
           artifact.sourceLogicalPath.startsWith("/Windows/System32/winevt/Logs/", Qt::CaseInsensitive) &&
           artifact.sourceLogicalPath.endsWith(".evtx", Qt::CaseInsensitive);
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
      out.summary = "Unable to read EVTX payload";
      return out;
    }
    if (bytes.size() < 4096) {
      out.state = domain::ArtifactParseState::Failed;
      out.summary = "EVTX file is truncated";
      out.error = "Input is smaller than EVTX header";
      return out;
    }
    if (!bytes.startsWith("ElfFile")) {
      out.state = domain::ArtifactParseState::Unsupported;
      out.summary = "Unsupported EVTX signature";
      return out;
    }

    domain::ArtifactDetails::EvtxLogEntry log;
    log.filePath = artifact.sourceLogicalPath;
    const QString kEvtxLogsRoot = "/Windows/System32/winevt/Logs/";
    if (artifact.sourceLogicalPath.startsWith(kEvtxLogsRoot, Qt::CaseInsensitive)) {
      log.logName = artifact.sourceLogicalPath.mid(kEvtxLogsRoot.size());
    } else {
      log.logName = artifact.sourceLogicalPath.section('/', -1);
    }
    constexpr int kHeaderSize = 4096;
    constexpr int kChunkSize = 65536;
    constexpr int kRecordCap = 1000;
    int parsedEvents = 0;
    int chunkCount = 0;

    for (int chunkBase = kHeaderSize; chunkBase + 8 <= bytes.size(); chunkBase += kChunkSize) {
      const QByteArray sig = bytes.mid(chunkBase, 8);
      if (sig == QByteArray(8, '\0')) continue;
      if (!sig.startsWith("ElfChnk")) {
        out.warnings.push_back(QString("Invalid EVTX chunk signature at offset %1").arg(chunkBase));
        continue;
      }
      chunkCount++;
      const quint32 firstRecordOffset = readLe32(bytes, chunkBase + 0x28);
      const quint32 freeSpaceOffset = readLe32(bytes, chunkBase + 0x30);
      quint32 cursor = (firstRecordOffset >= 0x200 && firstRecordOffset < static_cast<quint32>(kChunkSize))
                           ? firstRecordOffset
                           : 0x200;
      if (cursor != firstRecordOffset) {
        out.warnings.push_back(QString("EVTX chunk %1 has invalid first record offset; using 0x200").arg(chunkBase));
      }
      const quint32 bound = (freeSpaceOffset > cursor && freeSpaceOffset <= static_cast<quint32>(kChunkSize))
                                ? freeSpaceOffset
                                : static_cast<quint32>(kChunkSize);
      while (cursor + 8 <= bound && parsedEvents < kRecordCap) {
        bool ok = false;
        const quint32 recordSize = readLe32(bytes, chunkBase + static_cast<int>(cursor), &ok);
        if (!ok || recordSize == 0) break;
        if (recordSize < 32 || cursor + recordSize > static_cast<quint32>(kChunkSize) ||
            chunkBase + static_cast<int>(cursor + recordSize) > bytes.size()) {
          out.warnings.push_back(QString("Truncated or invalid EVTX record at chunk offset %1").arg(cursor));
          break;
        }
        const quint32 trailer = readLe32(bytes, chunkBase + static_cast<int>(cursor + recordSize - 4));
        if (trailer != recordSize) {
          out.warnings.push_back(QString("EVTX record size trailer mismatch at chunk offset %1").arg(cursor));
          break;
        }

        const QByteArray rec = bytes.mid(chunkBase + static_cast<int>(cursor), recordSize);
        domain::ArtifactDetails::EvtxEventEntry event;
        event.recordId = readLe64(rec, 8);
        event.timestamp = filetimeToUtc(readLe64(rec, 16));
        if (!detail::parseEvtxRecordPayload(rec, event)) {
          out.warnings.push_back(QString("Malformed EVTX BinXML payload at chunk offset %1").arg(cursor));
        }
        log.events.push_back(std::move(event));
        parsedEvents++;
        cursor += recordSize;
      }
    }
    if (parsedEvents >= kRecordCap) out.warnings.push_back("EVTX event extraction cap reached (1000 events)");
    if (chunkCount == 0) {
      out.state = domain::ArtifactParseState::Unsupported;
      out.summary = "No readable EVTX chunks found";
      return out;
    }

    if (!log.events.empty()) {
      log.recordCount = static_cast<int>(log.events.size());
      for (const auto &e : log.events) {
        if (!e.timestamp.has_value()) continue;
        if (!log.firstEventTimestamp || e.timestamp.value() < log.firstEventTimestamp.value()) {
          log.firstEventTimestamp = e.timestamp;
        }
        if (!log.lastEventTimestamp || e.timestamp.value() > log.lastEventTimestamp.value()) {
          log.lastEventTimestamp = e.timestamp;
        }
      }
    }

    const bool focused = log.logName.compare("Security.evtx", Qt::CaseInsensitive) == 0 ||
                         log.logName.compare("System.evtx", Qt::CaseInsensitive) == 0 ||
                         log.logName.compare("Application.evtx", Qt::CaseInsensitive) == 0 ||
                         log.logName.compare("Microsoft-Windows-Sysmon/Operational.evtx", Qt::CaseInsensitive) == 0;
    if (!focused) out.warnings.push_back("Non-primary EVTX channel parsed with generic v1 extraction");

    out.evtxLogEntries.push_back(std::move(log));
    if (out.evtxLogEntries.front().events.empty()) {
      out.state = domain::ArtifactParseState::Partial;
      out.summary = "EVTX parsed with no conservative events";
      return out;
    }
    out.state = out.warnings.isEmpty() ? domain::ArtifactParseState::Parsed : domain::ArtifactParseState::Partial;
    out.summary = "EVTX structural events parsed";
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

    const auto parsed = parseLnkSummaryFields(bytes);
    out.targetPath = parsed.targetPath;
    out.relativePath = parsed.relativePath;
    out.workingDirectory = parsed.workingDirectory;
    out.commandLineArguments = parsed.commandLineArguments;
    out.createdTimestamp = parsed.createdTimestamp;
    out.modifiedTimestamp = parsed.modifiedTimestamp;
    out.accessedTimestamp = parsed.accessedTimestamp;
    out.warnings = parsed.warnings;
    out.state = parsed.state;
    out.summary = parsed.summary;
    out.error = parsed.error;
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

class SrumProvider final : public IArtifactDetailProvider {
public:
  QString name() const override { return "windows.srum_metadata_probe"; }
  bool supports(const domain::ArtifactRecord &artifact) const override {
    const bool nameMatch = artifact.artifactName.compare("SRUM metadata probe", Qt::CaseInsensitive) == 0 ||
                           artifact.artifactName.compare("SRUM", Qt::CaseInsensitive) == 0;
    return nameMatch &&
           artifact.sourceLogicalPath.endsWith("SRUDB.dat", Qt::CaseInsensitive);
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
      out.summary = "Unable to read SRUM database";
      return out;
    }

    const auto parsed = detail_providers::parseSrumEsent(bytes);
    out.warnings = parsed.warnings;
    out.srumEseSignatureValid = parsed.validEse;
    out.srumPageSize = parsed.pageSize;
    out.srumParsedPageCount = parsed.parsedPageCount;
    out.srumParsedTagCount = parsed.parsedTagCount;
    for (const auto &table : parsed.tables) {
      out.srumTableEntries.push_back({table.tableId, table.tableName});
    }

    if (!parsed.validEse) {
      out.state = domain::ArtifactParseState::Failed;
      out.error = "SRUM ESE header validation failed";
      out.summary = "SRUM metadata probe failed";
      return out;
    }

    const bool sawTables = !out.srumTableEntries.empty();
    out.state = sawTables ? (out.warnings.isEmpty() ? domain::ArtifactParseState::Parsed
                                                    : domain::ArtifactParseState::Partial)
                          : domain::ArtifactParseState::Partial;
    out.summary = sawTables ? "SRUM metadata probe parsed"
                            : "SRUM metadata probe found no supported tables";
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
        providers.push_back(std::make_unique<AppCompatCacheProvider>());
        providers.push_back(std::make_unique<ServicesProvider>());
        providers.push_back(std::make_unique<UsbRegistryProvider>());
        providers.push_back(std::make_unique<ScheduledTaskProvider>());
        providers.push_back(std::make_unique<WerProvider>());
        providers.push_back(std::make_unique<EvtxProvider>());
        providers.push_back(std::make_unique<SrumProvider>());
        providers.push_back(std::make_unique<ChromiumHistoryProvider>());
        providers.push_back(std::make_unique<JumpListAutomaticProvider>());
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
