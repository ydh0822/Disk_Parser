#include "ForensicImageExtractor/forensics/FileSystemHandle.h"

#if defined(FIE_HAS_TSK)
#include <tsk/libtsk.h>
#endif

namespace fie::forensics {

FileSystemHandle::~FileSystemHandle() { close(); }

bool FileSystemHandle::open(const core::TskImageHandleAdapter &image,
                            const domain::PartitionInfo &partition,
                            QString &error) {
  close();
  if (!image.isOpen()) {
    error = "TSK image is not open";
    return false;
  }

#if defined(FIE_HAS_TSK)
  m_fs = tsk_fs_open_img(image.img(), static_cast<TSK_OFF_T>(partition.startOffset), TSK_FS_TYPE_DETECT);
  if (!m_fs) {
    error = QString("Filesystem open failed for %1: %2").arg(partition.identifier, tsk_error_get());
    return false;
  }
  m_type = QString::fromUtf8(tsk_fs_type_toname(m_fs->ftype));
  return true;
#else
  error = "TSK support is unavailable at build time";
  return false;
#endif
}

void FileSystemHandle::close() {
#if defined(FIE_HAS_TSK)
  if (m_fs) {
    tsk_fs_close(m_fs);
    m_fs = nullptr;
  }
#endif
  m_type.clear();
}

bool FileSystemHandle::isOpen() const { return m_fs != nullptr; }
QString FileSystemHandle::type() const { return m_type; }

domain::FileSystemCapabilities FileSystemHandle::capabilities() const {
  domain::FileSystemCapabilities caps;
#if defined(FIE_HAS_TSK)
  if (!m_fs) {
    return caps;
  }
  const auto ftype = m_fs->ftype;
  const bool isNtfs = ((ftype & TSK_FS_TYPE_ISNTFS) != 0);
  caps.supportsNtfsSiFnTimestamps = isNtfs;
  caps.supportsAds = isNtfs;
  caps.supportsDeletedState = true;
  caps.supportsStableFileId = true;
#else
  caps.supportsDeletedState = false;
  caps.supportsStableFileId = false;
#endif
  return caps;
}

TSK_FS_INFO *FileSystemHandle::fs() const { return m_fs; }

} // namespace fie::forensics
