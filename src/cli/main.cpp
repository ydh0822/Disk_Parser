#include "ForensicImageExtractor/cli/CliOptions.h"
#include "ForensicImageExtractor/core/ImageReaderFactory.h"
#include "ForensicImageExtractor/core/TskImageHandleAdapter.h"
#include "ForensicImageExtractor/forensics/ExtractionService.h"
#include "ForensicImageExtractor/forensics/FileSystemBrowser.h"
#include "ForensicImageExtractor/forensics/FileSystemHandle.h"
#include "ForensicImageExtractor/forensics/VolumeEnumerator.h"
#include "ForensicImageExtractor/utils/MetadataFactory.h"
#include "ForensicImageExtractor/utils/MetadataSerializerCsv.h"
#include "ForensicImageExtractor/utils/MetadataSerializerJson.h"

#include <QCoreApplication>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTextStream>

#include <optional>

namespace {

enum ExitCode {
  ExitOk = 0,
  ExitWarning = 2,
  ExitUsage = 64,
  ExitFailure = 1,
};

struct RuntimeState {
  std::shared_ptr<fie::core::IImageReader> reader;
  std::unique_ptr<fie::core::TskImageHandleAdapter> adapter;
  std::vector<fie::domain::PartitionInfo> partitions;
};

QString normalizedPath(QString path) {
  if (path.isEmpty()) {
    return "/";
  }
  if (!path.startsWith('/')) {
    path.prepend('/');
  }
  return path;
}

bool openImage(const fie::cli::ParsedOptions &opt, RuntimeState &state, QString &error, QString &warning) {
  auto readerUnique = fie::core::ImageReaderFactory::create(opt.imagePath);
  if (!readerUnique) {
    error = "Failed to create image reader";
    return false;
  }
  state.reader.reset(readerUnique.release());

  if (!state.reader->open(opt.imagePath, error)) {
    return false;
  }

  state.adapter = std::make_unique<fie::core::TskImageHandleAdapter>(state.reader, opt.allowPathFallback);
  if (!state.adapter->open(error)) {
    return false;
  }
  warning = state.adapter->lastWarning();
  return true;
}

bool loadPartitions(RuntimeState &state, QString &error) {
  fie::forensics::VolumeEnumerator enumerator;
  state.partitions = enumerator.enumerate(*state.adapter, error);
  return error.isEmpty();
}

bool resolvePartition(const QString &partitionArg,
                      const std::vector<fie::domain::PartitionInfo> &partitions,
                      fie::domain::PartitionInfo &out) {
  bool ok = false;
  const int index = partitionArg.toInt(&ok);
  for (const auto &partition : partitions) {
    if (partition.identifier == partitionArg || (ok && partition.index == index)) {
      out = partition;
      return true;
    }
  }
  return false;
}

std::optional<fie::domain::FileEntry> resolveEntry(const fie::forensics::FileSystemHandle &fs,
                                                   const QString &source,
                                                   QString &error) {
  fie::forensics::FileSystemBrowser browser;
  const QString normalized = normalizedPath(source);

#if defined(FIE_HAS_TSK)
  if (normalized == "/") {
    fie::domain::FileEntry root;
    root.name = "/";
    root.fullPath = "/";
    root.isDirectory = true;
    root.isAllocated = true;
    root.isDeleted = false;
    root.inode = static_cast<quint64>(fs.fs()->root_inum);
    root.capabilities = fs.capabilities();
    return root;
  }
#endif

  int split = normalized.lastIndexOf('/');
  QString parent = (split <= 0) ? "/" : normalized.left(split);
  const QString targetName = normalized.mid(split + 1);

  const auto entries = browser.listDirectory(fs, parent, error);
  if (!error.isEmpty()) {
    return std::nullopt;
  }

  for (const auto &entry : entries) {
    if (entry.name == targetName) {
      return entry;
    }
  }

  error = QString("Source path not found: %1").arg(normalized);
  return std::nullopt;
}

int runInspect(const RuntimeState &state, QTextStream &out) {
  QJsonArray rows;
  for (const auto &p : state.partitions) {
    QJsonObject o;
    o["index"] = p.index;
    o["identifier"] = p.identifier;
    o["start_offset"] = static_cast<qint64>(p.startOffset);
    o["length"] = static_cast<qint64>(p.length);
    o["description"] = p.description;
    o["filesystem_type"] = p.fileSystemType;
    rows.append(o);
  }
  out << QJsonDocument(rows).toJson(QJsonDocument::Compact) << Qt::endl;
  return ExitOk;
}

int runList(const RuntimeState &state, const fie::cli::ParsedOptions &opt, QTextStream &out, QString &error) {
  fie::domain::PartitionInfo partition;
  if (!resolvePartition(opt.partition, state.partitions, partition)) {
    error = QString("Unknown partition: %1").arg(opt.partition);
    return ExitFailure;
  }

  fie::forensics::FileSystemHandle fs;
  if (!fs.open(*state.adapter, partition, error)) {
    return ExitFailure;
  }

  fie::forensics::FileSystemBrowser browser;
  const auto entries = browser.listDirectory(fs, normalizedPath(opt.listPath), error);
  if (!error.isEmpty()) {
    return ExitFailure;
  }

  QJsonArray rows;
  for (const auto &e : entries) {
    QJsonObject o;
    o["path"] = e.fullPath;
    o["name"] = e.name;
    o["directory"] = e.isDirectory;
    o["deleted"] = e.isDeleted;
    o["allocated"] = e.isAllocated;
    o["inode"] = static_cast<qint64>(e.inode);
    o["size"] = static_cast<qint64>(e.sizeBytes);
    rows.append(o);
  }
  out << QJsonDocument(rows).toJson(QJsonDocument::Compact) << Qt::endl;
  return ExitOk;
}

int runExtractOrCatalog(const RuntimeState &state,
                        const fie::cli::ParsedOptions &opt,
                        QTextStream &out,
                        QString &error,
                        QStringList &warnings) {
  fie::domain::PartitionInfo partition;
  if (!resolvePartition(opt.partition, state.partitions, partition)) {
    error = QString("Unknown partition: %1").arg(opt.partition);
    return ExitFailure;
  }

  fie::forensics::FileSystemHandle fs;
  if (!fs.open(*state.adapter, partition, error)) {
    return ExitFailure;
  }

  auto source = resolveEntry(fs, opt.sourcePath, error);
  if (!source) {
    return ExitFailure;
  }

  fie::domain::ExtractionTask task;
  task.image.path = state.reader->path();
  task.image.sizeBytes = state.reader->size();
  task.image.format = fie::core::isEwfPath(task.image.path) ? "EWF" : "RAW/DD";
  task.partition = partition;
  task.entries = {*source};
  task.destinationRoot = opt.destinationRoot;
  task.settings.overwriteMode = opt.overwriteMode;
  task.settings.computeMd5 = opt.computeMd5;
  task.settings.applyHostTimestamps = opt.applyHostTimestamps;

  fie::forensics::ExtractionService extraction;
  auto results = extraction.extract(fs, task, error);
  if (!error.isEmpty()) {
    return ExitFailure;
  }

  std::vector<fie::domain::CatalogRecord> records;
  records.reserve(results.size());

  bool hardFail = false;
  bool hasWarning = false;
  for (const auto &r : results) {
    records.push_back(fie::utils::createCatalogRecord(task.image, partition, r));
    if (!r.error.isEmpty()) {
      hardFail = true;
    }
    if (!r.warning.isEmpty()) {
      hasWarning = true;
      warnings.push_back(r.warning);
    }
  }

  if (opt.command == fie::cli::CommandType::Catalog) {
    if (opt.catalogFormat == "json") {
      if (!fie::utils::MetadataSerializerJson::write(opt.catalogPath, records, error)) {
        return ExitFailure;
      }
    } else {
      if (!fie::utils::MetadataSerializerCsv::write(opt.catalogPath, records, error)) {
        return ExitFailure;
      }
    }
  }

  QJsonObject summary;
  summary["records"] = static_cast<int>(results.size());
  summary["hard_failures"] = hardFail;
  summary["warnings"] = hasWarning;
  if (opt.command == fie::cli::CommandType::Catalog) {
    summary["catalog_path"] = QFileInfo(opt.catalogPath).absoluteFilePath();
    summary["catalog_format"] = opt.catalogFormat;
  }
  out << QJsonDocument(summary).toJson(QJsonDocument::Compact) << Qt::endl;

  if (hardFail) {
    return ExitFailure;
  }
  return hasWarning ? ExitWarning : ExitOk;
}

} // namespace

int main(int argc, char *argv[]) {
  QCoreApplication app(argc, argv);
  QTextStream out(stdout);
  QTextStream err(stderr);

  const QStringList args = QCoreApplication::arguments();
  if (args.size() < 2 || args.contains("--help")) {
    out << fie::cli::usageText() << Qt::endl;
    return args.contains("--help") ? ExitOk : ExitUsage;
  }

  fie::cli::ParsedOptions opt;
  QString error;
  if (!fie::cli::parseOptions(args.mid(1), opt, error)) {
    err << "error=" << error << Qt::endl;
    err << fie::cli::usageText() << Qt::endl;
    return ExitUsage;
  }

  RuntimeState state;
  QString openWarning;
  if (!openImage(opt, state, error, openWarning)) {
    err << "error=" << error << Qt::endl;
    return ExitFailure;
  }

  if (!loadPartitions(state, error)) {
    err << "error=" << error << Qt::endl;
    return ExitFailure;
  }

  QStringList warnings;
  if (!openWarning.isEmpty()) {
    warnings.push_back(openWarning);
  }

  int rc = ExitFailure;
  switch (opt.command) {
  case fie::cli::CommandType::Inspect:
    rc = runInspect(state, out);
    break;
  case fie::cli::CommandType::List:
    rc = runList(state, opt, out, error);
    break;
  case fie::cli::CommandType::Extract:
  case fie::cli::CommandType::Catalog:
    rc = runExtractOrCatalog(state, opt, out, error, warnings);
    break;
  }

  if (!error.isEmpty()) {
    err << "error=" << error << Qt::endl;
    return ExitFailure;
  }

  for (const auto &warning : warnings) {
    err << "warning=" << warning << Qt::endl;
  }

  if (rc == ExitOk && !warnings.isEmpty()) {
    return ExitWarning;
  }
  return rc;
}
