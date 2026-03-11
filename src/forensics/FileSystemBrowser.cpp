#include "ForensicImageExtractor/forensics/FileSystemBrowser.h"

#if defined(FIE_HAS_TSK)
#include <tsk/libtsk.h>
#endif

#include <algorithm>

namespace fie::forensics {
namespace {
std::optional<QDateTime> toDateTime(time_t t) {
  if (t <= 0) {
    return std::nullopt;
  }
  return QDateTime::fromSecsSinceEpoch(static_cast<qint64>(t), Qt::UTC);
}
} // namespace

std::vector<domain::FileEntry> FileSystemBrowser::listDirectory(const FileSystemHandle &fs,
                                                                const QString &path,
                                                                QString &error) const {
  std::vector<domain::FileEntry> out;
  if (!fs.isOpen()) {
    error = "Filesystem is not open";
    return out;
  }

#if defined(FIE_HAS_TSK)
  const auto capabilities = fs.capabilities();
  QByteArray utf8Path = path.toUtf8();
  const char *dirPath = utf8Path.isEmpty() ? "/" : utf8Path.constData();
  TSK_FS_DIR *dir = tsk_fs_dir_open(fs.fs(), dirPath);
  if (!dir) {
    error = QString("Directory open failed for '%1': %2").arg(path, tsk_error_get());
    return out;
  }

  for (size_t i = 0; i < dir->names_used; ++i) {
    const TSK_FS_FILE *file = tsk_fs_dir_get(dir, i);
    if (!file || !file->name) {
      continue;
    }

    const QString name = QString::fromUtf8(file->name->name ? file->name->name : "");
    if (name == "." || name == "..") {
      continue;
    }

    domain::FileEntry entry;
    entry.name = name;
    entry.fullPath = (path.endsWith('/') ? path : path + "/") + name;
    entry.isDirectory = (file->name->type == TSK_FS_NAME_TYPE_DIR);
    entry.inode = file->name->meta_addr;
    const bool nameUnallocated = (file->name->flags & TSK_FS_NAME_FLAG_UNALLOC) != 0;
    const bool metaUnallocated =
        file->meta ? ((file->meta->flags & TSK_FS_META_FLAG_UNALLOC) != 0) : false;
    entry.isAllocated = !(nameUnallocated || metaUnallocated);
    entry.isDeleted = !entry.isAllocated;
    entry.capabilities = capabilities;

    if (file->meta) {
      entry.sizeBytes = static_cast<quint64>(file->meta->size);
      entry.metadata.timestamps.created = toDateTime(file->meta->crtime);
      entry.metadata.timestamps.modified = toDateTime(file->meta->mtime);
      entry.metadata.timestamps.entryModified = toDateTime(file->meta->ctime);
      entry.metadata.timestamps.accessed = toDateTime(file->meta->atime);

      if (capabilities.supportsAds || capabilities.supportsNtfsSiFnTimestamps) {
        domain::NtfsMetadata ntfs;
        ntfs.standardInfo = entry.metadata.timestamps;

        if (tsk_fs_file_attr_getsize(file) > 0) {
          for (int attrIndex = 0; attrIndex < tsk_fs_file_attr_getsize(file); ++attrIndex) {
            const TSK_FS_ATTR *attr = tsk_fs_file_attr_get_idx(file, attrIndex);
            if (!attr || attr->type != TSK_FS_ATTR_TYPE_NTFS_DATA) {
              continue;
            }
            if (attr->name && attr->name[0] != '\0') {
              ntfs.hasAds = true;
              ntfs.adsNames.push_back(QString::fromUtf8(attr->name));
            }
          }
        }

        ntfs.fileNameInfo.created = toDateTime(file->name->crtime);
        ntfs.fileNameInfo.modified = toDateTime(file->name->mtime);
        ntfs.fileNameInfo.entryModified = toDateTime(file->name->ctime);
        ntfs.fileNameInfo.accessed = toDateTime(file->name->atime);
        std::sort(ntfs.adsNames.begin(), ntfs.adsNames.end());
        ntfs.adsNames.erase(std::unique(ntfs.adsNames.begin(), ntfs.adsNames.end()), ntfs.adsNames.end());
        entry.metadata.ntfs = std::move(ntfs);
      }
    }

    out.push_back(std::move(entry));
  }

  tsk_fs_dir_close(dir);
#else
  error = "TSK support is unavailable at build time";
#endif

  return out;
}

} // namespace fie::forensics
