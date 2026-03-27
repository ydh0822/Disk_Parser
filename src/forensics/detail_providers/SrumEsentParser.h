#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>

#include <optional>
#include <vector>

namespace fie::forensics::detail_providers {

struct SrumTableObservation {
  QString tableId;
  QString tableName;
};

struct SrumEsentParseResult {
  bool validEse{false};
  std::optional<quint32> pageSize;
  std::optional<int> parsedPageCount;
  std::optional<int> parsedTagCount;
  std::vector<SrumTableObservation> tables;
  QStringList warnings;
};

SrumEsentParseResult parseSrumEsent(const QByteArray &bytes);

} // namespace fie::forensics::detail_providers
