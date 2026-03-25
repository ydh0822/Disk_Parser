#include "ForensicImageExtractor/forensics/RegistryHive.h"

#include <QStringDecoder>

namespace fie::forensics {

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

QString decodeUtf16(const QByteArray &bytes) {
  QStringDecoder decoder(QStringDecoder::Utf16LE);
  QString out = decoder.decode(bytes);
  const int nullPos = out.indexOf(QChar('\0'));
  return nullPos >= 0 ? out.left(nullPos) : out;
}

QString keySegmentDecode(const QByteArray &nameBytes) {
  bool zeroHeavy = false;
  for (int i = 1; i < nameBytes.size(); i += 2) {
    if (nameBytes[i] == '\0') {
      zeroHeavy = true;
      break;
    }
  }
  return zeroHeavy ? decodeUtf16(nameBytes) : QString::fromLatin1(nameBytes);
}

} // namespace

struct RegistryHive::State {
  QByteArray bytes;
  quint32 rootCellOffset{0};

  int cellAbs(quint32 rel) const { return 0x1000 + static_cast<int>(rel); }

  bool cellBody(quint32 rel, int &bodyOff, int &bodyLen) const {
    const int abs = cellAbs(rel);
    if (abs < 0 || abs + 4 > bytes.size()) return false;
    const qint32 rawSize = static_cast<qint32>(readLe32(bytes, abs));
    const int size = rawSize < 0 ? -rawSize : rawSize;
    if (size < 4 || abs + size > bytes.size()) return false;
    bodyOff = abs + 4;
    bodyLen = size - 4;
    return bodyLen >= 2;
  }

  std::optional<QString> nkName(quint32 nkRel) const {
    int off = 0;
    int len = 0;
    if (!cellBody(nkRel, off, len)) return std::nullopt;
    if (bytes.mid(off, 2) != QByteArray("nk", 2) || len < 0x50) return std::nullopt;
    const quint16 nameLen = readLe16(bytes, off + 0x48);
    if (off + 0x4C + static_cast<int>(nameLen) > bytes.size()) return std::nullopt;
    return keySegmentDecode(bytes.mid(off + 0x4C, nameLen));
  }

  std::optional<RegistryHive::Key> parseKey(quint32 nkRel) const {
    int off = 0;
    int len = 0;
    if (!cellBody(nkRel, off, len)) return std::nullopt;
    if (bytes.mid(off, 2) != QByteArray("nk", 2) || len < 0x4C) return std::nullopt;

    RegistryHive::Key key;
    key.lastWrite = filetimeToUtc(readLe64(bytes, off + 0x8));
    const quint16 nameLen = readLe16(bytes, off + 0x48);
    if (off + 0x4C + static_cast<int>(nameLen) > bytes.size()) return std::nullopt;

    const quint32 valueCount = readLe32(bytes, off + 0x24);
    const quint32 valueListRel = readLe32(bytes, off + 0x28);

    if (valueCount > 0 && valueListRel != 0xFFFFFFFF) {
      int listOff = 0;
      int listLen = 0;
      if (cellBody(valueListRel, listOff, listLen) && listLen >= static_cast<int>(valueCount * 4)) {
        for (quint32 i = 0; i < valueCount; ++i) {
          const quint32 vkRel = readLe32(bytes, listOff + static_cast<int>(i * 4));
          int vkOff = 0;
          int vkLen = 0;
          if (!cellBody(vkRel, vkOff, vkLen)) continue;
          if (bytes.mid(vkOff, 2) != QByteArray("vk", 2) || vkLen < 0x14) continue;

          RegistryHive::Value value;
          const quint16 vkNameLen = readLe16(bytes, vkOff + 0x2);
          const quint32 dataSizeRaw = readLe32(bytes, vkOff + 0x4);
          const quint32 dataRel = readLe32(bytes, vkOff + 0x8);
          value.type = readLe32(bytes, vkOff + 0xC);

          if (vkOff + 0x14 + static_cast<int>(vkNameLen) <= bytes.size() && vkNameLen > 0) {
            value.name = keySegmentDecode(bytes.mid(vkOff + 0x14, vkNameLen));
          }

          const bool inlineData = (dataSizeRaw & 0x80000000U) != 0;
          const quint32 dataSize = dataSizeRaw & 0x7FFFFFFFU;
          if (inlineData) {
            const QByteArray packed = bytes.mid(vkOff + 0x8, 4);
            value.rawData = packed.left(static_cast<int>(std::min<quint32>(dataSize, 4)));
          } else if (dataSize == 0 || dataRel == 0xFFFFFFFF) {
            value.rawData.clear();
          } else {
            int dataOff = 0;
            int dataLen = 0;
            if (!cellBody(dataRel, dataOff, dataLen)) continue;
            const int bytesToRead = std::min<int>(dataLen, static_cast<int>(dataSize));
            value.rawData = bytes.mid(dataOff, bytesToRead);
          }
          key.values.push_back(std::move(value));
        }
      }
    }

    return key;
  }

  std::vector<quint32> expandSubkeyList(quint32 rel) const {
    std::vector<quint32> out;
    int off = 0;
    int len = 0;
    if (!cellBody(rel, off, len) || len < 4) return out;
    const QByteArray sig = bytes.mid(off, 2);
    const quint16 count = readLe16(bytes, off + 2);

    if (sig == "li") {
      for (quint16 i = 0; i < count && (off + 4 + (i * 4) + 4) <= bytes.size(); ++i) {
        out.push_back(readLe32(bytes, off + 4 + (i * 4)));
      }
    } else if (sig == "lf" || sig == "lh") {
      for (quint16 i = 0; i < count && (off + 4 + (i * 8) + 4) <= bytes.size(); ++i) {
        out.push_back(readLe32(bytes, off + 4 + (i * 8)));
      }
    } else if (sig == "ri") {
      for (quint16 i = 0; i < count && (off + 4 + (i * 4) + 4) <= bytes.size(); ++i) {
        const quint32 sub = readLe32(bytes, off + 4 + (i * 4));
        const auto nested = expandSubkeyList(sub);
        out.insert(out.end(), nested.begin(), nested.end());
      }
    }
    return out;
  }
};

bool RegistryHive::open(const QByteArray &bytes, QString &error) {
  error.clear();
  if (bytes.size() < 0x1000) {
    error = "Registry hive is too small";
    return false;
  }
  if (bytes.mid(0, 4) != QByteArray("regf", 4)) {
    error = "Registry hive is missing regf signature";
    return false;
  }

  auto state = std::make_unique<State>();
  state->bytes = bytes;
  state->rootCellOffset = readLe32(bytes, 0x24);
  if (!state->parseKey(state->rootCellOffset).has_value()) {
    error = "Registry hive root cell is invalid";
    return false;
  }
  m_state = std::move(state);
  return true;
}

std::optional<RegistryHive::Key> RegistryHive::keyByPath(const QString &path, QString &error) const {
  error.clear();
  if (!m_state) {
    error = "Registry hive is not open";
    return std::nullopt;
  }

  QStringList parts = path.split('\\', Qt::SkipEmptyParts);
  quint32 current = m_state->rootCellOffset;

  QString builtPath;
  for (const auto &part : parts) {
    int off = 0;
    int len = 0;
    if (!m_state->cellBody(current, off, len) || m_state->bytes.mid(off, 2) != QByteArray("nk", 2)) {
      error = QString("Registry key path not found: %1").arg(path);
      return std::nullopt;
    }
    const quint32 subCount = readLe32(m_state->bytes, off + 0x14);
    const quint32 subListRel = readLe32(m_state->bytes, off + 0x1C);
    if (subCount == 0 || subListRel == 0xFFFFFFFF) {
      error = QString("Registry key path not found: %1").arg(path);
      return std::nullopt;
    }

    const auto subkeys = m_state->expandSubkeyList(subListRel);
    bool found = false;
    for (const auto rel : subkeys) {
      const auto name = m_state->nkName(rel);
      if (!name.has_value()) continue;
      if (name->compare(part, Qt::CaseInsensitive) == 0) {
        current = rel;
        builtPath += (builtPath.isEmpty() ? QString() : QString("\\")) + *name;
        found = true;
        break;
      }
    }
    if (!found) {
      error = QString("Registry key path not found: %1").arg(path);
      return std::nullopt;
    }
  }

  auto key = m_state->parseKey(current);
  if (!key.has_value()) {
    error = QString("Registry key parse failed: %1").arg(path);
    return std::nullopt;
  }
  key->path = builtPath;
  return key;
}

std::vector<RegistryHive::Key> RegistryHive::childKeys(const QString &path, QString &error) const {
  std::vector<Key> out;
  auto parent = keyByPath(path, error);
  if (!parent.has_value()) return out;

  QString parentErr;
  QStringList baseParts = parent->path.split('\\', Qt::SkipEmptyParts);
  quint32 current = m_state->rootCellOffset;
  for (const auto &part : baseParts) {
    int off = 0;
    int len = 0;
    if (!m_state->cellBody(current, off, len) || m_state->bytes.mid(off, 2) != QByteArray("nk", 2)) {
      error = QString("Registry child key enumeration failed: %1").arg(path);
      return {};
    }
    const quint32 subListRel = readLe32(m_state->bytes, off + 0x1C);
    bool found = false;
    for (const auto rel : m_state->expandSubkeyList(subListRel)) {
      const auto name = m_state->nkName(rel);
      if (name && name->compare(part, Qt::CaseInsensitive) == 0) {
        current = rel;
        found = true;
        break;
      }
    }
    if (!found) {
      error = QString("Registry child key enumeration failed: %1").arg(path);
      return {};
    }
  }

  int off = 0;
  int len = 0;
  if (!m_state->cellBody(current, off, len) || m_state->bytes.mid(off, 2) != QByteArray("nk", 2)) {
    error = QString("Registry child key enumeration failed: %1").arg(path);
    return {};
  }

  const quint32 subCount = readLe32(m_state->bytes, off + 0x14);
  const quint32 subListRel = readLe32(m_state->bytes, off + 0x1C);
  if (subCount == 0 || subListRel == 0xFFFFFFFF) return out;

  for (const auto rel : m_state->expandSubkeyList(subListRel)) {
    auto child = m_state->parseKey(rel);
    const auto childName = m_state->nkName(rel);
    if (!child || !childName) continue;
    child->path = parent->path.isEmpty() ? *childName : (parent->path + "\\" + *childName);
    out.push_back(std::move(*child));
  }

  return out;
}

QString decodeRegistryString(const RegistryHive::Value &value) {
  if (value.rawData.isEmpty()) return {};
  if (value.type == 1 || value.type == 2 || value.type == 7) {
    return decodeUtf16(value.rawData).trimmed();
  }
  return QString::fromLatin1(value.rawData).trimmed();
}

std::optional<quint32> decodeRegistryDword(const RegistryHive::Value &value) {
  if (value.type != 4 || value.rawData.size() < 4) return std::nullopt;
  return readLe32(value.rawData, 0);
}

} // namespace fie::forensics
