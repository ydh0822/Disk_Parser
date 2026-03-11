#include "ForensicImageExtractor/forensics/ExtractionService.h"

#include "ForensicImageExtractor/utils/ExtractionPlanner.h"
#include "ForensicImageExtractor/utils/TimestampPolicy.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSet>
#include <algorithm>

#if defined(FIE_HAS_TSK)
#include <tsk/libtsk.h>
#endif

namespace fie::forensics {
namespace {
constexpr size_t kChunkSize = 4 * 1024 * 1024;
constexpr int kMaxRecursionDepth = 256;

void emitProgress(const TaskContext *context, const ProgressInfo &info) {
  if (context && context->onProgress) {
    context->onProgress(info);
  }
}

bool cancelled(const TaskContext *context, QString &error) {
  if (context && context->isCancellationRequested()) {
    error = "Task cancelled";
    return true;
  }
  return false;
}

#if defined(FIE_HAS_TSK)
std::optional<QDateTime> toDateTime(time_t t) {
  if (t <= 0) {
    return std::nullopt;
  }
  return QDateTime::fromSecsSinceEpoch(static_cast<qint64>(t), Qt::UTC);
}

fie::domain::FileEntry toChildEntry(const TSK_FS_FILE *file, const QString &parentPath,
                                    const fie::domain::FileSystemCapabilities &capabilities) {
  fie::domain::FileEntry e;
  const QString name = QString::fromUtf8(file->name->name ? file->name->name : "");
  e.name = name;
  e.fullPath = parentPath.endsWith('/') ? parentPath + name : parentPath + '/' + name;
  e.isDirectory = (file->name->type == TSK_FS_NAME_TYPE_DIR);
  e.inode = file->name->meta_addr;
  e.isAllocated = !(file->name->flags & TSK_FS_NAME_FLAG_UNALLOC);
  e.isDeleted = !e.isAllocated;
  e.capabilities = capabilities;
  if (file->meta) {
    e.sizeBytes = static_cast<quint64>(file->meta->size);
    e.metadata.timestamps.created = toDateTime(file->meta->crtime);
    e.metadata.timestamps.modified = toDateTime(file->meta->mtime);
    e.metadata.timestamps.entryModified = toDateTime(file->meta->ctime);
    e.metadata.timestamps.accessed = toDateTime(file->meta->atime);

    if (capabilities.supportsAds || capabilities.supportsNtfsSiFnTimestamps) {
      fie::domain::NtfsMetadata ntfs;
      ntfs.standardInfo = e.metadata.timestamps;
      const int attrCount = tsk_fs_file_attr_getsize(file);
      for (int attrIdx = 0; attrIdx < attrCount; ++attrIdx) {
        const TSK_FS_ATTR *attr = tsk_fs_file_attr_get_idx(file, attrIdx);
        if (!attr || attr->type != TSK_FS_ATTR_TYPE_NTFS_DATA) {
          continue;
        }
        if (attr->name && attr->name[0] != '\0') {
          ntfs.hasAds = true;
          ntfs.adsNames.push_back(QString::fromUtf8(attr->name));
        }
      }
      ntfs.fileNameInfo.created = toDateTime(file->name->crtime);
      ntfs.fileNameInfo.modified = toDateTime(file->name->mtime);
      ntfs.fileNameInfo.entryModified = toDateTime(file->name->ctime);
      ntfs.fileNameInfo.accessed = toDateTime(file->name->atime);
      e.metadata.ntfs = std::move(ntfs);
    }
  }
  return e;
}

void collectRecursive(const FileSystemHandle &fs,
                      const fie::domain::FileEntry &seed,
                      std::vector<fie::domain::FileEntry> &out,
                      QSet<QString> &visitedPaths,
                      QSet<quint64> &visitedDirInodes,
                      const fie::domain::FileSystemCapabilities &capabilities,
                      int depth,
                      QString &error,
                      const TaskContext *context) {
  if (cancelled(context, error)) {
    return;
  }
  if (depth > kMaxRecursionDepth) {
    error = QString("Recursion depth exceeded at path: %1").arg(seed.fullPath);
    return;
  }

  if (visitedPaths.contains(seed.fullPath)) {
    return;
  }
  visitedPaths.insert(seed.fullPath);
  out.push_back(seed);

  if (!seed.isDirectory) {
    return;
  }

  if (seed.inode != 0 && visitedDirInodes.contains(seed.inode)) {
    return;
  }
  if (seed.inode != 0) {
    visitedDirInodes.insert(seed.inode);
  }

  TSK_FS_DIR *dir = tsk_fs_dir_open_meta(fs.fs(), static_cast<TSK_INUM_T>(seed.inode));
  if (!dir) {
    error = QString("Failed to open directory inode %1 for recursion: %2").arg(seed.inode).arg(tsk_error_get());
    return;
  }

  for (size_t i = 0; i < dir->names_used; ++i) {
    if (cancelled(context, error)) {
      break;
    }
    const TSK_FS_FILE *file = tsk_fs_dir_get(dir, i);
    if (!file || !file->name || !file->name->name) {
      continue;
    }
    const QString name = QString::fromUtf8(file->name->name);
    if (name == "." || name == "..") {
      continue;
    }

    auto child = toChildEntry(file, seed.fullPath, capabilities);
    collectRecursive(fs, child, out, visitedPaths, visitedDirInodes, capabilities, depth + 1, error, context);
    if (!error.isEmpty()) {
      break;
    }
  }

  tsk_fs_dir_close(dir);
}
#endif

} // namespace

bool ExtractionService::simulateChunkLoopForTesting(quint64 totalBytes,
                                                    quint64 chunkSize,
                                                    QString &error,
                                                    const TaskContext *context) {
  if (chunkSize == 0) {
    error = "chunkSize must be greater than 0";
    return false;
  }

  quint64 processed = 0;
  while (processed < totalBytes) {
    if (cancelled(context, error)) {
      return false;
    }
    const quint64 step = std::min(chunkSize, totalBytes - processed);
    processed += step;
    ProgressInfo progress;
    progress.currentPath = "/simulated";
    progress.currentFileIndex = 1;
    progress.totalFiles = 1;
    progress.fileBytesProcessed = processed;
    progress.fileBytesTotal = totalBytes;
    progress.totalBytesProcessed = processed;
    progress.totalBytesEstimated = totalBytes;
    emitProgress(context, progress);
  }
  return true;
}

std::vector<domain::ExtractionResult> ExtractionService::extract(const FileSystemHandle &fs,
                                                                 const domain::ExtractionTask &task,
                                                                 QString &error,
                                                                 const TaskContext *context) const {
  std::vector<domain::ExtractionResult> results;
  if (!fs.isOpen()) {
    error = "Cannot extract: filesystem not open";
    return results;
  }

#if defined(FIE_HAS_TSK)
  std::vector<domain::FileEntry> worklist;
  const auto capabilities = fs.capabilities();
  QSet<QString> seenPaths;
  QSet<quint64> seenDirInodes;
  for (const auto &entry : task.entries) {
    std::vector<domain::FileEntry> expanded;
    collectRecursive(fs, entry, expanded, seenPaths, seenDirInodes, capabilities, 0, error, context);
    if (!error.isEmpty()) {
      return results;
    }
    for (auto &x : expanded) {
      worklist.push_back(std::move(x));
    }
  }

  quint64 totalBytesEstimated = 0;
  for (const auto &e : worklist) {
    if (!e.isDirectory) {
      totalBytesEstimated += e.sizeBytes;
    }
  }
  quint64 totalBytesProcessed = 0;

  for (int idx = 0; idx < static_cast<int>(worklist.size()); ++idx) {
    if (cancelled(context, error)) {
      return results;
    }
    const auto &entry = worklist[static_cast<size_t>(idx)];
    domain::ExtractionResult res;
    res.source = entry;
    const QString requestedPath = utils::composeDestinationPath(task.destinationRoot, entry.fullPath);

    if (entry.isDirectory) {
      if (!QDir().mkpath(requestedPath)) {
        res.primaryOutcome = "directory_create_failed";
        res.status = res.primaryOutcome;
        res.error = QString("Failed to create directory: %1").arg(requestedPath);
      } else {
        res.primaryOutcome = "directory_created";
        res.status = res.primaryOutcome;
        res.destinationPath = requestedPath;
      }
      ProgressInfo progress;
      progress.currentPath = entry.fullPath;
      progress.currentFileIndex = idx + 1;
      progress.totalFiles = static_cast<int>(worklist.size());
      progress.fileBytesProcessed = 0;
      progress.fileBytesTotal = 0;
      progress.totalBytesProcessed = totalBytesProcessed;
      progress.totalBytesEstimated = totalBytesEstimated;
      emitProgress(context, progress);
      results.push_back(res);
      continue;
    }

    if (entry.inode == 0) {
      res.primaryOutcome = "invalid_inode";
      res.status = res.primaryOutcome;
      res.error = "Missing/invalid inode for file extraction";
      results.push_back(res);
      continue;
    }

    QString decision;
    const QString destinationPath = utils::resolveDestinationPath(requestedPath, task.settings.overwriteMode, decision);
    if (decision == "skipped_existing") {
      res.primaryOutcome = "skipped_existing";
      res.status = res.primaryOutcome;
      res.destinationPath = destinationPath;
      res.bytesWritten = 0;
      totalBytesProcessed += entry.sizeBytes;
      ProgressInfo progress;
      progress.currentPath = entry.fullPath;
      progress.currentFileIndex = idx + 1;
      progress.totalFiles = static_cast<int>(worklist.size());
      progress.fileBytesProcessed = entry.sizeBytes;
      progress.fileBytesTotal = entry.sizeBytes;
      progress.totalBytesProcessed = totalBytesProcessed;
      progress.totalBytesEstimated = totalBytesEstimated;
      emitProgress(context, progress);
      results.push_back(res);
      continue;
    }

    QDir().mkpath(QFileInfo(destinationPath).path());

    TSK_FS_FILE *tskFile = tsk_fs_file_open_meta(fs.fs(), nullptr, static_cast<TSK_INUM_T>(entry.inode));
    if (!tskFile || !tskFile->meta) {
      res.primaryOutcome = "open_failed";
      res.status = res.primaryOutcome;
      res.error = QString("Unable to open inode %1 for extraction: %2").arg(entry.inode).arg(tsk_error_get());
      if (tskFile) {
        tsk_fs_file_close(tskFile);
      }
      results.push_back(res);
      continue;
    }

    QFile out(destinationPath);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
      tsk_fs_file_close(tskFile);
      res.primaryOutcome = "write_open_failed";
      res.status = res.primaryOutcome;
      res.error = QString("Output open failed: %1").arg(out.errorString());
      results.push_back(res);
      continue;
    }

    QCryptographicHash sha256(QCryptographicHash::Sha256);
    QCryptographicHash md5(QCryptographicHash::Md5);
    QByteArray buffer(static_cast<qsizetype>(kChunkSize), Qt::Uninitialized);

    const quint64 expectedSize = entry.sizeBytes;
    quint64 offset = 0;
    quint64 totalWritten = 0;
    bool readFailed = false;
    bool writeFailed = false;

    while (offset < expectedSize) {
      if (cancelled(context, error)) {
        out.close();
        tsk_fs_file_close(tskFile);
        return results;
      }
      const quint64 remaining = expectedSize - offset;
      const size_t ask = static_cast<size_t>(std::min<quint64>(remaining, kChunkSize));
      const auto got = tsk_fs_file_read(tskFile, static_cast<TSK_OFF_T>(offset), buffer.data(), ask,
                                        TSK_FS_FILE_READ_FLAG_NONE);
      if (got < 0) {
        readFailed = true;
        res.primaryOutcome = "read_failed";
        res.status = res.primaryOutcome;
        res.error = QString("TSK read failed at offset %1 for inode %2: %3")
                        .arg(offset)
                        .arg(entry.inode)
                        .arg(tsk_error_get());
        break;
      }
      if (got == 0) {
        break;
      }

      const auto written = out.write(buffer.constData(), got);
      if (written != got) {
        writeFailed = true;
        res.primaryOutcome = "write_failed";
        res.status = res.primaryOutcome;
        res.error = QString("Output write failed at offset %1: %2").arg(offset).arg(out.errorString());
        break;
      }

      sha256.addData(buffer.constData(), got);
      if (task.settings.computeMd5) {
        md5.addData(buffer.constData(), got);
      }

      offset += static_cast<quint64>(got);
      totalWritten += static_cast<quint64>(written);
      ProgressInfo progress;
      progress.currentPath = entry.fullPath;
      progress.currentFileIndex = idx + 1;
      progress.totalFiles = static_cast<int>(worklist.size());
      progress.fileBytesProcessed = totalWritten;
      progress.fileBytesTotal = expectedSize;
      progress.totalBytesProcessed = totalBytesProcessed + totalWritten;
      progress.totalBytesEstimated = totalBytesEstimated;
      emitProgress(context, progress);
    }

    out.close();
    tsk_fs_file_close(tskFile);

    res.bytesWritten = totalWritten;
    totalBytesProcessed += totalWritten;

    if (readFailed || writeFailed) {
      res.destinationPath = destinationPath;
      res.error = QString("%1 | bytes_written=%2").arg(res.error).arg(totalWritten);
      results.push_back(res);
      continue;
    }

    res.destinationPath = destinationPath;
    res.sha256 = QString(sha256.result().toHex());
    if (task.settings.computeMd5) {
      res.md5 = QString(md5.result().toHex());
    }

    res.primaryOutcome = utils::successOutcomeFromDecision(decision);

    if (totalWritten != expectedSize) {
      res.primaryOutcome = "short_read";
      res.warning = QString("bytes_written=%1 expected=%2").arg(totalWritten).arg(expectedSize);
    }

    if (task.settings.applyHostTimestamps) {
      QString tsError;
      res.hostTimestampsApplied = utils::TimestampPolicy::applyHostFileTimes(destinationPath, entry, tsError);
      if (!res.hostTimestampsApplied) {
        res.hostTimestampError = tsError;
        if (!res.warning.isEmpty()) {
          res.warning += " | ";
        }
        res.warning += tsError;
      }
    }

    res.status = utils::finalStatusFromOutcome(res.primaryOutcome, !res.warning.isEmpty(), !res.error.isEmpty());

    results.push_back(res);
  }
#else
  Q_UNUSED(task)
  Q_UNUSED(context)
  error = "TSK support is unavailable at build time";
#endif

  return results;
}

} // namespace fie::forensics
