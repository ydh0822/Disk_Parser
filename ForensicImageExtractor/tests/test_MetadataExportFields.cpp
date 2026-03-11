#include "ForensicImageExtractor/utils/MetadataSerializerCsv.h"
#include "ForensicImageExtractor/utils/MetadataSerializerJson.h"

#include <QFile>

int runMetadataExportFieldTests() {
  fie::domain::CatalogRecord r;
  r.sourceImagePath = "img.dd";
  r.partitionIdentifier = "p1";
  r.warning = "non-fatal";
  r.hostTimestampsApplied = false;
  r.hostTimestampError = "failed";
  r.bytesWritten = 123;

  std::vector<fie::domain::CatalogRecord> rows{r};
  QString error;
  const QString jsonPath = "/tmp/fie_catalog_test.json";
  const QString csvPath = "/tmp/fie_catalog_test.csv";
  if (!fie::utils::MetadataSerializerJson::write(jsonPath, rows, error)) return 1;
  if (!fie::utils::MetadataSerializerCsv::write(csvPath, rows, error)) return 1;

  QFile json(jsonPath);
  if (!json.open(QIODevice::ReadOnly)) return 1;
  const auto jsonText = json.readAll();
  if (!jsonText.contains("host_timestamps_applied") || !jsonText.contains("bytes_written") ||
      !jsonText.contains("warning"))
    return 1;

  QFile csv(csvPath);
  if (!csv.open(QIODevice::ReadOnly)) return 1;
  const auto csvText = csv.readAll();
  if (!csvText.contains("host_timestamps_applied") || !csvText.contains("bytes_written") ||
      !csvText.contains("warning") || !csvText.contains("non-fatal"))
    return 1;

  return 0;
}
