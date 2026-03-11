#pragma once

#include "ForensicImageExtractor/domain/Models.h"

#include <QString>

namespace fie::utils {

class TimestampPolicy {
public:
  static bool applyHostFileTimes(const QString &path, const domain::FileEntry &entry, QString &error);
};

} // namespace fie::utils
