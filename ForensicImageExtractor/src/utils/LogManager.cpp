#include "ForensicImageExtractor/utils/LogManager.h"

#include <QDateTime>

namespace fie::utils {

LogManager::LogManager(QObject *parent) : QObject(parent) {}

void LogManager::info(const QString &message) {
  const auto line = QString("[%1] INFO  %2").arg(QDateTime::currentDateTimeUtc().toString(Qt::ISODate),
                                                 message);
  m_entries.append(line);
  emit logAdded(line);
}

void LogManager::error(const QString &message) {
  const auto line = QString("[%1] ERROR %2").arg(QDateTime::currentDateTimeUtc().toString(Qt::ISODate),
                                                 message);
  m_entries.append(line);
  emit logAdded(line);
}

const QStringList &LogManager::entries() const { return m_entries; }

} // namespace fie::utils
