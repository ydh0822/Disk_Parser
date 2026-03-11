#pragma once

#include "ForensicImageExtractor/domain/Models.h"
#include "ForensicImageExtractor/forensics/FileSystemHandle.h"

#include <vector>

namespace fie::forensics {

class FileSystemBrowser {
public:
  std::vector<domain::FileEntry> listDirectory(const FileSystemHandle &fs, const QString &path,
                                               QString &error) const;
};

} // namespace fie::forensics
