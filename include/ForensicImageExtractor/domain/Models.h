#pragma once

#include <QDateTime>
#include <QMetaType>
#include <QString>
#include <QStringList>
#include <optional>
#include <vector>

namespace fie::domain {

struct TimestampSet {
  std::optional<QDateTime> created;
  std::optional<QDateTime> modified;
  std::optional<QDateTime> entryModified;
  std::optional<QDateTime> accessed;
};

struct NtfsMetadata {
  TimestampSet standardInfo;
  TimestampSet fileNameInfo;
  bool hasAds{false};
  QStringList adsNames;
  QString attributes;
};

struct FileSystemCapabilities {
  bool supportsNtfsSiFnTimestamps{false};
  bool supportsAds{false};
  bool supportsDeletedState{true};
  bool supportsStableFileId{true};
};

struct GenericFileMetadata {
  TimestampSet timestamps;
  QString attributes;
  std::optional<NtfsMetadata> ntfs;
};

struct ImageInfo {
  QString path;
  QString format;
  quint64 sizeBytes{0};
};

enum class ForensicOperationState {
  Success,
  SuccessWithWarning,
  Failure,
};

enum class ForensicBackend {
  ReaderBridge,
  PathFallback,
  Unknown,
  NotApplicable,
};

struct ForensicDiagnostic {
  QString reason;
  QString userMessage;
  QString detail;
};

struct ForensicOperationResult {
  ForensicOperationState state{ForensicOperationState::Failure};
  ForensicBackend backend{ForensicBackend::NotApplicable};
  ForensicDiagnostic diagnostic;

  bool succeeded() const { return state != ForensicOperationState::Failure; }
  bool hasWarning() const { return state == ForensicOperationState::SuccessWithWarning; }
};

struct PartitionInfo {
  int index{-1};
  QString identifier;
  quint64 startOffset{0};
  quint64 length{0};
  QString description;
  QString fileSystemType;
};

struct FileEntry {
  QString name;
  QString fullPath;
  bool isDirectory{false};
  bool isDeleted{false};
  bool isAllocated{true};
  quint64 sizeBytes{0};
  quint64 inode{0};
  GenericFileMetadata metadata;
  FileSystemCapabilities capabilities;
};


struct ArtifactRecord {
  QString category;
  QString artifactName;
  QString profile;
  QString sourceLogicalPath;
  QString status;
  bool directoryTarget{false};
  quint64 sizeBytes{0};
  std::optional<QDateTime> keyTimestamp;
  QString partitionIdentifier;
  QString fileSystemType;
  QString notes;
};

enum class OverwriteMode { SkipExisting, Overwrite, VersionedCopy };

struct AppSettings {
  OverwriteMode overwriteMode{OverwriteMode::SkipExisting};
  bool computeMd5{false};
  bool applyHostTimestamps{false};
};

struct ExtractionTask {
  ImageInfo image;
  PartitionInfo partition;
  std::vector<FileEntry> entries;
  QString destinationRoot;
  AppSettings settings;
};

struct ExtractionResult {
  FileEntry source;
  QString destinationPath;
  QString sha256;
  QString md5;
  QString primaryOutcome;
  QString status;
  QString error;
  QString warning;
  quint64 bytesWritten{0};
  bool hostTimestampsApplied{false};
  QString hostTimestampError;
};

struct CatalogRecord {
  QString sourceImagePath;
  QString partitionIdentifier;
  QString logicalPath;
  QString fileName;
  quint64 fileSize{0};
  quint64 inode{0};
  bool deleted{false};
  bool allocated{true};
  TimestampSet siTimestamps;
  TimestampSet fnTimestamps;
  QStringList adsNames;
  QString primaryOutcome;
  QString extractionStatus;
  QString destinationPath;
  QString sha256;
  QString md5;
  QString error;
  QString warning;
  quint64 bytesWritten{0};
  bool hostTimestampsApplied{false};
  QString hostTimestampError;
};

} // namespace fie::domain

Q_DECLARE_METATYPE(fie::domain::ImageInfo)
Q_DECLARE_METATYPE(fie::domain::ForensicOperationResult)
Q_DECLARE_METATYPE(fie::domain::PartitionInfo)
Q_DECLARE_METATYPE(fie::domain::FileEntry)
Q_DECLARE_METATYPE(fie::domain::ExtractionResult)
Q_DECLARE_METATYPE(fie::domain::ArtifactRecord)
Q_DECLARE_METATYPE(std::vector<fie::domain::PartitionInfo>)
Q_DECLARE_METATYPE(std::vector<fie::domain::FileEntry>)
Q_DECLARE_METATYPE(std::vector<fie::domain::ExtractionResult>)
Q_DECLARE_METATYPE(std::vector<fie::domain::ArtifactRecord>)
