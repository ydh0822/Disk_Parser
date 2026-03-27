#include "SrumEsentParser.h"

#include <QSet>

namespace fie::forensics::detail_providers {
namespace {

quint16 readLe16(const QByteArray &bytes, int offset, bool *ok = nullptr) {
  if (offset < 0 || offset + 2 > bytes.size()) {
    if (ok) *ok = false;
    return 0;
  }
  if (ok) *ok = true;
  return static_cast<quint16>(static_cast<quint8>(bytes[offset])) |
         (static_cast<quint16>(static_cast<quint8>(bytes[offset + 1])) << 8);
}

quint32 readLe32(const QByteArray &bytes, int offset, bool *ok = nullptr) {
  if (offset < 0 || offset + 4 > bytes.size()) {
    if (ok) *ok = false;
    return 0;
  }
  if (ok) *ok = true;
  return static_cast<quint32>(static_cast<quint8>(bytes[offset])) |
         (static_cast<quint32>(static_cast<quint8>(bytes[offset + 1])) << 8) |
         (static_cast<quint32>(static_cast<quint8>(bytes[offset + 2])) << 16) |
         (static_cast<quint32>(static_cast<quint8>(bytes[offset + 3])) << 24);
}

QByteArray toUtf16Le(const QString &text) {
  return QByteArray(reinterpret_cast<const char *>(text.utf16()), text.size() * 2);
}

bool containsToken(const QByteArray &haystack, const QString &token) {
  if (token.isEmpty()) return false;
  const QByteArray ascii = token.toUtf8();
  if (haystack.contains(ascii)) return true;
  return haystack.contains(toUtf16Le(token));
}

struct TableToken {
  QString id;
  QString name;
};

const std::vector<TableToken> kSupportedTokens{
    {"{DD6636C4-8929-4683-974E-22C046A43763}", "application_resource_usage"},
    {"{973F5D5C-1D90-4944-BE8E-24B94231A174}", "network_data_usage"},
    {"{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}", "network_connectivity"},
    {"{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}", "energy_usage"},
};

std::vector<QByteArray> extractTaggedPayloadsFromPage(const QByteArray &page, QStringList &warnings) {
  std::vector<QByteArray> out;
  if (page.size() < 64) return out;

  // Conservative slotted-page parse for ESE-like page layout:
  // offsets chosen to avoid blind whole-file scanning. If page metadata is not
  // coherent, the page is skipped (no token fallback outside tags).
  bool tagCountOk = false;
  const quint16 tagCount = readLe16(page, 0x16, &tagCountOk);
  if (!tagCountOk || tagCount == 0 || tagCount > 1024) return out;

  const int tagDirectoryOffset = page.size() - static_cast<int>(tagCount) * 4;
  if (tagDirectoryOffset < 32 || tagDirectoryOffset >= page.size()) return out;

  for (quint16 i = 0; i < tagCount; ++i) {
    bool ibOk = false;
    bool cbOk = false;
    const int entryOff = tagDirectoryOffset + static_cast<int>(i) * 4;
    const quint16 ib = readLe16(page, entryOff, &ibOk);
    const quint16 cb = readLe16(page, entryOff + 2, &cbOk);
    if (!ibOk || !cbOk) continue;
    if (cb == 0) continue;
    if (ib < 32 || static_cast<int>(ib) + static_cast<int>(cb) > tagDirectoryOffset) {
      warnings.push_back("SRUM page tag directory contains out-of-range payload pointer");
      continue;
    }
    out.push_back(page.mid(ib, cb));
  }
  return out;
}

} // namespace

SrumEsentParseResult parseSrumEsent(const QByteArray &bytes) {
  SrumEsentParseResult out;
  if (bytes.size() < 512) {
    out.warnings.push_back("SRUM payload is too short for ESE header validation");
    return out;
  }

  static const QByteArray kEseSignature = QByteArray::fromHex("EFCDAB89");
  if (bytes.mid(4, 4) != kEseSignature) {
    out.warnings.push_back("SRUM ESE signature not found at expected header offset");
    return out;
  }
  out.validEse = true;

  bool pageSizeOk = false;
  const quint32 pageSize = readLe32(bytes, 236, &pageSizeOk);
  if (!pageSizeOk || (pageSize != 2048 && pageSize != 4096 && pageSize != 8192 && pageSize != 16384 && pageSize != 32768)) {
    out.warnings.push_back("SRUM page size is unavailable or outside expected ESE ranges");
    return out;
  }
  out.pageSize = pageSize;

  const int pageCount = bytes.size() / static_cast<int>(pageSize);
  out.parsedPageCount = pageCount > 0 ? std::optional<int>(pageCount - 1) : std::optional<int>(0);
  if (pageCount <= 1) {
    out.warnings.push_back("SRUM payload contains no ESE data pages");
    return out;
  }

  QSet<QString> seenTables;
  int parsedTags = 0;
  for (int pg = 1; pg < pageCount; ++pg) {
    const QByteArray page = bytes.mid(pg * static_cast<int>(pageSize), static_cast<int>(pageSize));
    auto taggedPayloads = extractTaggedPayloadsFromPage(page, out.warnings);
    parsedTags += static_cast<int>(taggedPayloads.size());
    for (const auto &payload : taggedPayloads) {
      // Scope guard: this parser intentionally remains metadata-probe-only.
      // It does not decode ESE rows/cells from payloads in this revision.
      for (const auto &token : kSupportedTokens) {
        if (!containsToken(payload, token.id)) continue;
        if (!seenTables.contains(token.id)) {
          seenTables.insert(token.id);
          out.tables.push_back({token.id, token.name});
        }
      }
    }
  }
  out.parsedTagCount = parsedTags;

  if (out.tables.empty()) {
    out.warnings.push_back("No supported SRUM tables were discovered from parsed ESE page-tag payloads");
  }
  return out;
}

} // namespace fie::forensics::detail_providers
