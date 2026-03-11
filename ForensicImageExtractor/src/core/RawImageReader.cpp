#include "ForensicImageExtractor/core/RawImageReader.h"

namespace fie::core {

bool RawImageReader::open(const QString &imagePath, QString &error) {
  close();
  m_file.setFileName(imagePath);
  if (!m_file.open(QIODevice::ReadOnly)) {
    error = QString("Unable to open image '%1': %2").arg(imagePath, m_file.errorString());
    return false;
  }
  return true;
}

void RawImageReader::close() {
  if (m_file.isOpen()) {
    m_file.close();
  }
}

QByteArray RawImageReader::read(quint64 offset, quint64 size, QString &error) {
  if (!isOpen()) {
    error = "Image is not open";
    return {};
  }
  if (!m_file.seek(static_cast<qint64>(offset))) {
    error = QString("Seek failed at offset %1").arg(offset);
    return {};
  }
  auto data = m_file.read(static_cast<qint64>(size));
  if (data.size() < 0) {
    error = QString("Read failed at offset %1").arg(offset);
    return {};
  }
  return data;
}

quint64 RawImageReader::size() const { return static_cast<quint64>(m_file.size()); }

bool RawImageReader::isOpen() const { return m_file.isOpen(); }

QString RawImageReader::path() const { return m_file.fileName(); }
QString RawImageReader::lastWarning() const { return {}; }

} // namespace fie::core
