#pragma once

#include <QByteArray>
#include <QString>

namespace fie::core {

class IImageReader {
public:
  virtual ~IImageReader() = default;
  virtual bool open(const QString &imagePath, QString &error) = 0;
  virtual void close() = 0;
  virtual QByteArray read(quint64 offset, quint64 size, QString &error) = 0;
  virtual quint64 size() const = 0;
  virtual bool isOpen() const = 0;
  virtual QString path() const = 0;
  virtual QString lastWarning() const { return {}; }
};

} // namespace fie::core
