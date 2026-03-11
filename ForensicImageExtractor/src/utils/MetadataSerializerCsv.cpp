#include "ForensicImageExtractor/utils/MetadataSerializerCsv.h"

#include <QFile>
#include <QTextStream>

namespace fie::utils {
namespace {
QString q(const QString &in) {
  QString out = in;
  out.replace('"', "\"\"");
  return '"' + out + '"';
}
QString fmt(const std::optional<QDateTime> &dt) { return dt ? dt->toString(Qt::ISODate) : ""; }
} // namespace

bool MetadataSerializerCsv::write(const QString &path,
                                  const std::vector<domain::CatalogRecord> &records,
                                  QString &error) {
  QFile file(path);
  if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
    error = QString("Unable to write CSV catalog '%1': %2").arg(path, file.errorString());
    return false;
  }

  QTextStream out(&file);
  out << "source_image_path,partition_identifier,logical_path,file_name,size,inode_mft,deleted,allocated,"
         "si_created,si_modified,si_entry_modified,si_accessed,fn_created,fn_modified,fn_entry_modified,fn_accessed,"
         "destination_path,sha256,primary_outcome,status,error,warning,bytes_written,host_timestamps_applied,host_timestamp_error\n";

  for (const auto &r : records) {
    out << q(r.sourceImagePath) << ',' << q(r.partitionIdentifier) << ',' << q(r.logicalPath) << ','
        << q(r.fileName) << ',' << r.fileSize << ',' << r.inode << ',' << (r.deleted ? "true" : "false") << ','
        << (r.allocated ? "true" : "false") << ',' << q(fmt(r.siTimestamps.created)) << ','
        << q(fmt(r.siTimestamps.modified)) << ',' << q(fmt(r.siTimestamps.entryModified)) << ','
        << q(fmt(r.siTimestamps.accessed)) << ',' << q(fmt(r.fnTimestamps.created)) << ','
        << q(fmt(r.fnTimestamps.modified)) << ',' << q(fmt(r.fnTimestamps.entryModified)) << ','
        << q(fmt(r.fnTimestamps.accessed)) << ',' << q(r.destinationPath) << ',' << q(r.sha256) << ','
        << q(r.primaryOutcome) << ',' << q(r.extractionStatus) << ',' << q(r.error) << ',' << q(r.warning) << ',' << r.bytesWritten << ','
        << (r.hostTimestampsApplied ? "true" : "false") << ',' << q(r.hostTimestampError) << '\n';
  }

  return true;
}

} // namespace fie::utils
