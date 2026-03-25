#pragma once

#include "ForensicImageExtractor/forensics/FileSystemHandle.h"

#include <QByteArray>
#include <QString>

namespace fie::forensics {

QByteArray readFileBytesByPath(const FileSystemHandle &fs,
                               const QString &fullPath,
                               quint64 maxBytes,
                               QString &error);

} // namespace fie::forensics
