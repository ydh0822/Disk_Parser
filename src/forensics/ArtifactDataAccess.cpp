#include "ForensicImageExtractor/forensics/ArtifactDataAccess.h"

#include "ForensicImageExtractor/forensics/FileSystemBrowser.h"

#if defined(FIE_HAS_TSK)
#include <tsk/libtsk.h>
#endif
#include <algorithm>

namespace fie::forensics {
namespace {

QString normalizePath(QString path) {
  path.replace('\\', '/');
  if (path.isEmpty()) return "/";
  if (!path.startsWith('/')) path.prepend('/');
  while (path.contains("//")) path.replace("//", "/");
  if (path.size() > 1 && path.endsWith('/')) path.chop(1);
  return path;
}

QString parentPath(const QString &path) {
  const auto normalized = normalizePath(path);
  const int slash = normalized.lastIndexOf('/');
  if (slash <= 0) return "/";
  return normalized.left(slash);
}

QString baseName(const QString &path) {
  const auto normalized = normalizePath(path);
  const int slash = normalized.lastIndexOf('/');
  return slash < 0 ? normalized : normalized.mid(slash + 1);
}

} // namespace

QByteArray readFileBytesByPath(const FileSystemHandle &fs,
                               const QString &fullPath,
                               quint64 maxBytes,
                               QString &error) {
  QByteArray out;
  if (!fs.isOpen()) {
    error = "Filesystem is not open";
    return out;
  }

#if defined(FIE_HAS_TSK)
  FileSystemBrowser browser;
  QString listError;
  const auto parentEntries = browser.listDirectory(fs, parentPath(fullPath), listError);
  if (!listError.isEmpty()) {
    error = listError;
    return out;
  }

  domain::FileEntry target;
  bool found = false;
  const auto name = baseName(fullPath);
  for (const auto &entry : parentEntries) {
    if (entry.name.compare(name, Qt::CaseInsensitive) == 0) {
      target = entry;
      found = true;
      break;
    }
  }
  if (!found) {
    error = QString("Path not found: %1").arg(fullPath);
    return out;
  }
  if (target.isDirectory) {
    error = QString("Path is a directory and cannot be parsed as an artifact file: %1").arg(fullPath);
    return out;
  }

  TSK_FS_FILE *tskFile = tsk_fs_file_open_meta(fs.fs(), nullptr, static_cast<TSK_INUM_T>(target.inode));
  if (!tskFile) {
    error = QString("Artifact open failed: %1").arg(tsk_error_get());
    return out;
  }

  const auto capped = std::min<quint64>(target.sizeBytes, maxBytes);
  out.resize(static_cast<int>(capped));
  const ssize_t got = tsk_fs_file_read(tskFile, 0, out.data(), static_cast<size_t>(capped), TSK_FS_FILE_READ_FLAG_NONE);
  tsk_fs_file_close(tskFile);
  if (got < 0) {
    out.clear();
    error = QString("Artifact read failed: %1").arg(tsk_error_get());
    return out;
  }
  out.resize(static_cast<int>(got));
#else
  Q_UNUSED(fullPath)
  Q_UNUSED(maxBytes)
  error = "TSK support is unavailable at build time";
#endif

  return out;
}

} // namespace fie::forensics
