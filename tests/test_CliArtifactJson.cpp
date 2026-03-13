#include "ForensicImageExtractor/cli/ArtifactJson.h"

#include <QJsonArray>
#include <QJsonObject>

int runCliArtifactJsonTests() {
  fie::domain::ArtifactRecord b;
  b.category = "Execution";
  b.artifactName = "Prefetch";
  b.profile = "SYSTEM";
  b.sourceLogicalPath = "/Windows/Prefetch";
  b.status = "Present";
  b.directoryTarget = true;
  b.partitionIdentifier = "p0";
  b.fileSystemType = "NTFS";

  fie::domain::ArtifactRecord a;
  a.category = "Browser";
  a.artifactName = "Chrome History";
  a.profile = "Alice";
  a.sourceLogicalPath = "/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/History";
  a.status = "Present";
  a.sizeBytes = 1234;
  a.partitionIdentifier = "p0";
  a.fileSystemType = "NTFS";
  a.notes = "SQLite parsing deferred";

  QJsonArray rows = fie::cli::artifactsToJsonArray({b, a});
  if (rows.size() != 2) return 1;

  const auto first = rows.at(0).toObject();
  const auto second = rows.at(1).toObject();

  if (first.value("category").toString() != "Browser") return 1;
  if (first.value("artifact_name").toString() != "Chrome History") return 1;
  if (first.value("source_logical_path").toString().isEmpty()) return 1;
  if (!first.contains("status") || !first.contains("notes") || !first.contains("partition_identifier")) return 1;

  if (second.value("category").toString() != "Execution") return 1;
  if (!second.contains("directory_target") || !second.contains("size_bytes") || !second.contains("key_timestamp")) return 1;

  return 0;
}
