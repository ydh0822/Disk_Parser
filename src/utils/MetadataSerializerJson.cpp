#include "ForensicImageExtractor/utils/MetadataSerializerJson.h"

#include "ForensicImageExtractor/utils/TimestampSerializer.h"

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

namespace fie::utils {

bool MetadataSerializerJson::write(const QString &path,
                                   const std::vector<domain::CatalogRecord> &records,
                                   QString &error) {
  QJsonArray rows;
  for (const auto &r : records) {
    QJsonObject obj;
    obj["source_image_path"] = r.sourceImagePath;
    obj["partition_identifier"] = r.partitionIdentifier;
    obj["logical_path"] = r.logicalPath;
    obj["file_name"] = r.fileName;
    obj["size"] = static_cast<qint64>(r.fileSize);
    obj["inode_mft"] = static_cast<qint64>(r.inode);
    obj["deleted"] = r.deleted;
    obj["allocated"] = r.allocated;
    obj["si_timestamps"] = serializeTimestampSet(r.siTimestamps);
    obj["fn_timestamps"] = serializeTimestampSet(r.fnTimestamps);
    QJsonArray adsNames;
    for (const auto &name : r.adsNames) {
      adsNames.append(name);
    }
    obj["ads_names"] = adsNames;
    obj["destination_path"] = r.destinationPath;
    obj["sha256"] = r.sha256;
    obj["md5"] = r.md5;
    obj["primary_outcome"] = r.primaryOutcome;
    obj["status"] = r.extractionStatus;
    obj["error"] = r.error;
    obj["warning"] = r.warning;
    obj["bytes_written"] = static_cast<qint64>(r.bytesWritten);
    obj["host_timestamps_applied"] = r.hostTimestampsApplied;
    obj["host_timestamp_error"] = r.hostTimestampError;
    rows.append(obj);
  }

  QFile file(path);
  if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
    error = QString("Unable to write JSON catalog '%1': %2").arg(path, file.errorString());
    return false;
  }
  file.write(QJsonDocument(rows).toJson(QJsonDocument::Indented));
  return true;
}

} // namespace fie::utils
