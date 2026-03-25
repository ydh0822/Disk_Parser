#pragma once

#include <QByteArray>
#include <QTemporaryFile>

#include <functional>
#include <memory>

namespace fie::forensics {

struct MaterializedArtifact {
  std::unique_ptr<QTemporaryFile> file;
  QString sourceLogicalPath;

  bool valid() const { return file && file->isOpen(); }
  QString localPath() const { return file ? file->fileName() : QString(); }
};

MaterializedArtifact materializeArtifactReadOnly(
    const QString &sourceLogicalPath,
    const std::function<QByteArray(const QString &, QString &)> &readBytes,
    QString &error);

} // namespace fie::forensics
