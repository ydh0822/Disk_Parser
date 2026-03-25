#include "ForensicImageExtractor/forensics/ArtifactMaterializationService.h"

namespace fie::forensics {

MaterializedArtifact materializeArtifactReadOnly(
    const QString &sourceLogicalPath,
    const std::function<QByteArray(const QString &, QString &)> &readBytes,
    QString &error) {
  MaterializedArtifact out;
  out.sourceLogicalPath = sourceLogicalPath;
  if (!readBytes) {
    error = "No artifact read callback available";
    return out;
  }

  const QByteArray bytes = readBytes(sourceLogicalPath, error);
  if (!error.isEmpty()) return out;

  auto temp = std::make_unique<QTemporaryFile>("fie_artifact_XXXXXX.tmp");
  temp->setAutoRemove(true);
  if (!temp->open()) {
    error = "Failed to open temporary file for artifact materialization";
    return out;
  }
  if (temp->write(bytes) != bytes.size()) {
    error = "Failed to write materialized artifact bytes";
    return out;
  }
  temp->flush();

  out.file = std::move(temp);
  return out;
}

} // namespace fie::forensics
