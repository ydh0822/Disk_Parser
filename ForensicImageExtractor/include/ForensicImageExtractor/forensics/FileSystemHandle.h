#pragma once

#include "ForensicImageExtractor/core/TskImageHandleAdapter.h"
#include "ForensicImageExtractor/domain/Models.h"

struct TSK_FS_INFO;

namespace fie::forensics {

class FileSystemHandle {
public:
  FileSystemHandle() = default;
  ~FileSystemHandle();

  bool open(const core::TskImageHandleAdapter &image, const domain::PartitionInfo &partition,
            QString &error);
  void close();
  bool isOpen() const;
  QString type() const;
  TSK_FS_INFO *fs() const;

private:
  TSK_FS_INFO *m_fs{nullptr};
  QString m_type;
};

} // namespace fie::forensics
