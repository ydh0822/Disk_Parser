#pragma once

#include "ForensicImageExtractor/domain/Models.h"

#include <QString>
#include <vector>

namespace fie::utils {

class MetadataSerializerJson {
public:
  static bool write(const QString &path, const std::vector<domain::CatalogRecord> &records, QString &error);
};

} // namespace fie::utils
