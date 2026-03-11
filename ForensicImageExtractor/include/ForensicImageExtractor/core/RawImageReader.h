#pragma once

#include "ForensicImageExtractor/core/IImageReader.h"

#include <QFile>

namespace fie::core {

class RawImageReader final : public IImageReader {
public:
  bool open(const QString &imagePath, QString &error) override;
  void close() override;
  QByteArray read(quint64 offset, quint64 size, QString &error) override;
  quint64 size() const override;
  bool isOpen() const override;
  QString path() const override;
  QString lastWarning() const override;

private:
  QFile m_file;
};

} // namespace fie::core
