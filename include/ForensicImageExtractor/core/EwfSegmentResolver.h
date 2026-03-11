#pragma once

#include <QString>
#include <QStringList>

namespace fie::core {

bool isEwfPath(const QString &imagePath);
QStringList discoverEwfSegments(const QString &selectedPath, const QStringList &fileNamesInDir,
                                QString *warning = nullptr);

} // namespace fie::core
