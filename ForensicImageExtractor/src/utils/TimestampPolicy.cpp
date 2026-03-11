#include "ForensicImageExtractor/utils/TimestampPolicy.h"

#include <QFile>

namespace fie::utils {

bool TimestampPolicy::applyHostFileTimes(const QString &path, const domain::FileEntry &entry, QString &error) {
  QFile file(path);
  if (!file.open(QIODevice::ReadWrite)) {
    error = QString("Cannot open extracted file for timestamp update: %1").arg(file.errorString());
    return false;
  }

  bool ok = true;
  if (entry.metadata.timestamps.modified) {
    ok = ok && file.setFileTime(*entry.metadata.timestamps.modified, QFileDevice::FileModificationTime);
  }
  if (entry.metadata.timestamps.accessed) {
    ok = ok && file.setFileTime(*entry.metadata.timestamps.accessed, QFileDevice::FileAccessTime);
  }
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
  if (entry.metadata.timestamps.created) {
    ok = ok && file.setFileTime(*entry.metadata.timestamps.created, QFileDevice::FileBirthTime);
  }
#endif

  if (!ok) {
    error = "One or more host timestamps could not be applied";
  }
  return ok;
}

} // namespace fie::utils
