#include "EvtxBinXmlParser.h"

#include <QStringDecoder>

namespace fie::forensics::detail {
namespace {

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

std::optional<quint32> parseOptionalUInt(const QString &value) {
  bool ok = false;
  const auto n = value.trimmed().toUInt(&ok, 0);
  return ok ? std::optional<quint32>(n) : std::nullopt;
}

} // namespace

bool parseEvtxRecordPayload(const QByteArray &record, domain::ArtifactDetails::EvtxEventEntry &event) {
  if (record.size() < 32) return false;
  const QByteArray payload = record.mid(24, record.size() - 28);
  if (payload.size() < 8) return false;
  if (static_cast<quint8>(payload[0]) != 0x0F || static_cast<quint8>(payload[1]) != 0x01 ||
      static_cast<quint8>(payload[2]) != 0x01) {
    return false;
  }

  int off = 4;
  constexpr int kMaxDepth = 24;
  bool sawTerminator = false;
  bool sawRootEvent = false;
  QStringList substitutionValues;
  auto readSizedUtf16At = [&](int &cursor, QString &out) -> bool {
    bool ok = false;
    const quint16 chars = readLe16(payload, cursor, &ok);
    if (!ok) return false;
    cursor += 2;
    const int bytesLen = static_cast<int>(chars) * 2;
    if (cursor + bytesLen > payload.size()) return false;
    QStringDecoder dec(QStringDecoder::Utf16LE);
    out = dec.decode(payload.mid(cursor, bytesLen)).trimmed();
    cursor += bytesLen;
    return true;
  };
  auto readNameString = [&](quint32 nameOffset, QString &nameOut) -> bool {
    if (nameOffset >= static_cast<quint32>(payload.size())) return false;
    int cursor = static_cast<int>(nameOffset);
    bool ok = false;
    (void)readLe32(payload, cursor, &ok); // next-string offset (unused)
    if (!ok) return false;
    cursor += 4;
    const quint16 hash = readLe16(payload, cursor, &ok);
    if (!ok) return false;
    Q_UNUSED(hash);
    cursor += 2;
    const quint16 chars = readLe16(payload, cursor, &ok);
    if (!ok) return false;
    cursor += 2;
    const int bytesLen = static_cast<int>(chars) * 2;
    if (cursor + bytesLen > payload.size()) return false;
    QStringDecoder dec(QStringDecoder::Utf16LE);
    nameOut = dec.decode(payload.mid(cursor, bytesLen)).trimmed();
    if (cursor + bytesLen + 2 <= payload.size()) {
      const quint16 trailingNull = readLe16(payload, cursor + bytesLen);
      if (trailingNull != 0) return false;
    }
    return !nameOut.isEmpty();
  };
  auto readTextValueToken = [&](int &cursor, QString &out) -> bool {
    if (cursor >= payload.size()) return false;
    const quint8 valueToken = static_cast<quint8>(payload[cursor++]);
    if ((valueToken & 0x0F) != 0x05) return false;
    return readSizedUtf16At(cursor, out);
  };
  auto readSubstitutionToken = [&](int &cursor, QString &out) -> bool {
    if (cursor + 4 > payload.size()) return false;
    bool ok = false;
    const quint16 index = readLe16(payload, cursor, &ok);
    if (!ok) return false;
    cursor += 2;
    const quint8 valueType = static_cast<quint8>(payload[cursor++]);
    const quint8 reserved = static_cast<quint8>(payload[cursor++]);
    Q_UNUSED(valueType);
    Q_UNUSED(reserved);
    if (index >= static_cast<quint16>(substitutionValues.size())) return false;
    out = substitutionValues[static_cast<int>(index)];
    return true;
  };
  auto readInlineTemplateSubstitutions = [&]() {
    if (off >= payload.size()) return true;
    const quint8 token = static_cast<quint8>(payload[off]);
    if ((token & 0x0F) != 0x0C) return true;
    if (off + 4 > payload.size()) return false;
    off += 1; // template marker token
    off += 1; // reserved
    bool ok = false;
    const quint16 count = readLe16(payload, off, &ok);
    if (!ok) return false;
    off += 2;
    for (quint16 i = 0; i < count; ++i) {
      if (off + 4 > payload.size()) return false;
      const quint16 size = readLe16(payload, off, &ok);
      if (!ok) return false;
      off += 2;
      const quint8 type = static_cast<quint8>(payload[off++]);
      off += 1; // reserved
      if (off + size > payload.size()) return false;
      QString value;
      if (type == 0x01 && size >= 2 && (size % 2) == 0) {
        QStringDecoder dec(QStringDecoder::Utf16LE);
        value = dec.decode(payload.mid(off, size)).trimmed();
      }
      substitutionValues.push_back(value);
      off += size;
    }
    return true;
  };

  bool consumed = false;
  QStringList stack;
  QString pendingDataKey;
  if (!readInlineTemplateSubstitutions()) return false;
  while (off < payload.size()) {
    const quint8 token = static_cast<quint8>(payload[off++]);
    const quint8 tokenBase = token & 0x0F;
    if (token == 0x00 || token == 0xFF) {
      sawTerminator = true;
      break;
    }
    if (tokenBase == 0x01) {
      bool ok = false;
      const quint16 dep = readLe16(payload, off, &ok);
      if (!ok) return false;
      Q_UNUSED(dep);
      off += 2;
      const quint32 dataSize = readLe32(payload, off, &ok);
      if (!ok) return false;
      Q_UNUSED(dataSize);
      off += 4;
      const quint32 nameOffset = readLe32(payload, off, &ok);
      if (!ok) return false;
      off += 4;
      QString name;
      if (!readNameString(nameOffset, name)) return false;
      stack.push_back(name);
      if (stack.size() > kMaxDepth) return false;
      if (stack.size() == 1 && name.compare("Event", Qt::CaseInsensitive) == 0) sawRootEvent = true;
      if ((token & 0x40) != 0) {
        const quint32 attrCount = readLe32(payload, off, &ok);
        if (!ok) return false;
        Q_UNUSED(attrCount);
        off += 4;
      }
      continue;
    }
    if (tokenBase == 0x02 || tokenBase == 0x03) continue;
    if (tokenBase == 0x04) {
      if (stack.isEmpty()) return false;
      stack.pop_back();
      pendingDataKey.clear();
      continue;
    }
    if (tokenBase == 0x06) {
      bool ok = false;
      const quint32 attrNameOffset = readLe32(payload, off, &ok);
      if (!ok) return false;
      off += 4;
      QString attrName;
      if (!readNameString(attrNameOffset, attrName)) return false;
      QString attrValue;
      if (off >= payload.size()) return false;
      const quint8 attrToken = static_cast<quint8>(payload[off]);
      const quint8 attrBase = attrToken & 0x0F;
      if (attrBase == 0x05) {
        if (!readTextValueToken(off, attrValue)) return false;
      } else if (attrBase == 0x0D || attrBase == 0x0E) {
        off += 1;
        if (!readSubstitutionToken(off, attrValue)) return false;
      } else {
        return false;
      }
      if (stack.isEmpty()) return false;
      const QString path = stack.join('/');
      if (path.endsWith("Event/System/Provider", Qt::CaseInsensitive) &&
          attrName.compare("Name", Qt::CaseInsensitive) == 0) {
        event.providerName = attrValue;
        consumed = consumed || !event.providerName.isEmpty();
      } else if (path.endsWith("Event/System/TimeCreated", Qt::CaseInsensitive) &&
                 attrName.compare("SystemTime", Qt::CaseInsensitive) == 0) {
        const auto dt = QDateTime::fromString(attrValue, Qt::ISODate);
        if (dt.isValid()) {
          event.timestamp = dt.toUTC();
          consumed = true;
        }
      } else if (path.endsWith("Event/EventData/Data", Qt::CaseInsensitive) &&
                 attrName.compare("Name", Qt::CaseInsensitive) == 0) {
        pendingDataKey = attrValue;
      }
      continue;
    }
    if (tokenBase == 0x05) {
      QString value;
      if (!readSizedUtf16At(off, value)) return false;
      const QString path = stack.join('/');
      if (path.endsWith("Event/System/EventID", Qt::CaseInsensitive)) {
        event.eventId = parseOptionalUInt(value);
        consumed = consumed || event.eventId.has_value();
      } else if (path.endsWith("Event/System/Level", Qt::CaseInsensitive)) {
        event.level = parseOptionalUInt(value);
        consumed = consumed || event.level.has_value();
      } else if (path.endsWith("Event/System/Computer", Qt::CaseInsensitive)) {
        event.computer = value;
        consumed = consumed || !event.computer.isEmpty();
      } else if (path.endsWith("Event/System/Opcode", Qt::CaseInsensitive)) {
        event.opcode = parseOptionalUInt(value);
        consumed = consumed || event.opcode.has_value();
      } else if (path.endsWith("Event/System/Task", Qt::CaseInsensitive)) {
        event.task = parseOptionalUInt(value);
        consumed = consumed || event.task.has_value();
      } else if (path.endsWith("Event/System/Keywords", Qt::CaseInsensitive)) {
        event.keywords = value;
        consumed = consumed || !event.keywords.isEmpty();
      } else if (path.endsWith("Event/EventData/Data", Qt::CaseInsensitive)) {
        if (!pendingDataKey.isEmpty() || !value.isEmpty()) {
          event.eventData.push_back(QString("%1=%2").arg(pendingDataKey, value));
          consumed = true;
        }
        pendingDataKey.clear();
      }
      continue;
    }
    if (tokenBase == 0x0D || tokenBase == 0x0E) {
      QString value;
      if (!readSubstitutionToken(off, value)) return false;
      const QString path = stack.join('/');
      if (path.endsWith("Event/System/EventID", Qt::CaseInsensitive)) {
        event.eventId = parseOptionalUInt(value);
        consumed = consumed || event.eventId.has_value();
      } else if (path.endsWith("Event/System/Level", Qt::CaseInsensitive)) {
        event.level = parseOptionalUInt(value);
        consumed = consumed || event.level.has_value();
      } else if (path.endsWith("Event/System/Computer", Qt::CaseInsensitive)) {
        event.computer = value;
        consumed = consumed || !event.computer.isEmpty();
      } else if (path.endsWith("Event/System/Opcode", Qt::CaseInsensitive)) {
        event.opcode = parseOptionalUInt(value);
        consumed = consumed || event.opcode.has_value();
      } else if (path.endsWith("Event/System/Task", Qt::CaseInsensitive)) {
        event.task = parseOptionalUInt(value);
        consumed = consumed || event.task.has_value();
      } else if (path.endsWith("Event/System/Keywords", Qt::CaseInsensitive)) {
        event.keywords = value;
        consumed = consumed || !event.keywords.isEmpty();
      } else if (path.endsWith("Event/EventData/Data", Qt::CaseInsensitive)) {
        if (!pendingDataKey.isEmpty() || !value.isEmpty()) {
          event.eventData.push_back(QString("%1=%2").arg(pendingDataKey, value));
          consumed = true;
        }
        pendingDataKey.clear();
      }
      continue;
    }
    return false;
  }
  if (!sawRootEvent) return false;
  if (!sawTerminator) return false;
  if (!stack.isEmpty()) return false;
  return consumed;
}

} // namespace fie::forensics::detail
