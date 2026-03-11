#include "ForensicImageExtractor/utils/ExtractionPlanner.h"
#include "ForensicImageExtractor/utils/MetadataFactory.h"
#include "ForensicImageExtractor/utils/MetadataSerializerCsv.h"
#include "ForensicImageExtractor/utils/MetadataSerializerJson.h"

#include <QDir>
#include <QFile>

int runForensicEdgeCaseTests() {
  // Deterministic extraction taxonomy for short reads and warning/error composition.
  if (fie::utils::finalStatusFromOutcome("short_read", true, false) != "short_read") {
    return 1;
  }
  if (fie::utils::finalStatusFromOutcome("success_overwrite", true, false) != "success_with_warning") {
    return 1;
  }

  // Duplicate destination collisions remain deterministic through overwrite planner.
  const QString base = QDir::currentPath() + "/.edge_collision.bin";
  {
    QFile f(base);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
      return 1;
    }
    f.write("existing");
  }

  QString decision;
  const QString skippedPath = fie::utils::resolveDestinationPath(base, fie::domain::OverwriteMode::SkipExisting, decision);
  if (decision != "skipped_existing" || skippedPath != base) {
    QFile::remove(base);
    return 1;
  }

  const QString versionedPath =
      fie::utils::resolveDestinationPath(base, fie::domain::OverwriteMode::VersionedCopy, decision);
  if (decision != "versioned_copy" || versionedPath == base || !versionedPath.contains("_copy")) {
    QFile::remove(base);
    return 1;
  }
  QFile::remove(base);

  // Metadata fidelity and deterministic ADS normalization/dedup for forensic reporting.
  fie::domain::ImageInfo image;
  image.path = "case.E01";

  fie::domain::PartitionInfo partition;
  partition.identifier = "p1";

  fie::domain::ExtractionResult result;
  result.source.fullPath = "/Users/alice/report.txt";
  result.source.name = "report.txt";
  result.source.sizeBytes = 0; // zero-byte edge case
  result.source.inode = 123;
  result.source.isAllocated = false;
  result.source.isDeleted = true; // deleted-entry edge case
  result.primaryOutcome = "short_read";
  result.status = "short_read";
  result.warning = "short_read bytes_written=0 expected=512 possible_sparse_or_unreadable | source_entry_deleted";
  result.error.clear();
  result.bytesWritten = 0;
  result.hostTimestampsApplied = false;
  result.hostTimestampError = "One or more host timestamps could not be applied";

  fie::domain::NtfsMetadata ntfs;
  ntfs.hasAds = true;
  ntfs.adsNames = {"Zone.Identifier", "Secret", "Zone.Identifier"}; // duplicate ADS name edge case
  result.source.metadata.ntfs = ntfs;

  const auto rec = fie::utils::createCatalogRecord(image, partition, result);
  if (!rec.deleted || rec.allocated || rec.fileSize != 0 || rec.bytesWritten != 0) {
    return 1;
  }
  if (rec.adsNames.size() != 2 || rec.adsNames[0] != "Secret" || rec.adsNames[1] != "Zone.Identifier") {
    return 1;
  }
  if (rec.hostTimestampsApplied || rec.hostTimestampError.isEmpty()) {
    return 1;
  }

  const QString jsonPath = QDir::currentPath() + "/.forensic_edge_cases.json";
  const QString csvPath = QDir::currentPath() + "/.forensic_edge_cases.csv";
  QString error;
  const std::vector<fie::domain::CatalogRecord> rows{rec};

  if (!fie::utils::MetadataSerializerJson::write(jsonPath, rows, error)) {
    return 1;
  }
  if (!fie::utils::MetadataSerializerCsv::write(csvPath, rows, error)) {
    QFile::remove(jsonPath);
    return 1;
  }

  QFile jf(jsonPath);
  if (!jf.open(QIODevice::ReadOnly)) {
    QFile::remove(jsonPath);
    QFile::remove(csvPath);
    return 1;
  }
  const QByteArray jsonText = jf.readAll();

  QFile cf(csvPath);
  if (!cf.open(QIODevice::ReadOnly)) {
    QFile::remove(jsonPath);
    QFile::remove(csvPath);
    return 1;
  }
  const QByteArray csvText = cf.readAll();

  QFile::remove(jsonPath);
  QFile::remove(csvPath);

  if (!jsonText.contains("\"ads_names\"") || !jsonText.contains("Zone.Identifier") ||
      !jsonText.contains("host_timestamp_error") || !jsonText.contains("short_read") ||
      !jsonText.contains("possible_sparse_or_unreadable") || !jsonText.contains("source_entry_deleted")) {
    return 1;
  }

  if (!csvText.contains("ads_names") || !csvText.contains("Secret;Zone.Identifier") ||
      !csvText.contains("host_timestamp_error") || !csvText.contains("short_read") ||
      !csvText.contains("source_entry_deleted")) {
    return 1;
  }

  return 0;
}
