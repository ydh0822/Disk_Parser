#pragma once

#include <QObject>
#include <QStringList>

namespace fie::utils {

class LogManager : public QObject {
  Q_OBJECT
public:
  explicit LogManager(QObject *parent = nullptr);
  void info(const QString &message);
  void error(const QString &message);
  const QStringList &entries() const;

signals:
  void logAdded(const QString &line);

private:
  QStringList m_entries;
};

} // namespace fie::utils
