#pragma once

#include "ForensicImageExtractor/domain/Models.h"

#include <QString>
#include <QStringList>

namespace fie::cli {

enum class CommandType { Inspect, List, Extract, Catalog };

struct ParsedOptions {
  CommandType command{CommandType::Inspect};
  QString imagePath;
  QString partition{"p0"};
  QString sourcePath{"/"};
  QString listPath{"/"};
  QString destinationRoot;
  QString catalogPath;
  QString catalogFormat{"json"};
  bool allowPathFallback{false};
  domain::OverwriteMode overwriteMode{domain::OverwriteMode::SkipExisting};
  bool computeMd5{false};
  bool applyHostTimestamps{false};
};

bool parseOptions(const QStringList &args, ParsedOptions &out, QString &error);
QString usageText();

} // namespace fie::cli
