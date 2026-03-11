#include "ForensicImageExtractor/core/EwfImageReader.h"
#include "ForensicImageExtractor/core/EwfSegmentResolver.h"

#if defined(FIE_HAS_LIBEWF)
#include <libewf.h>
#endif

#include <QDir>
#include <QFileInfo>
#include <limits>
#include <vector>

namespace fie::core {
EwfImageReader::~EwfImageReader() { close(); }

bool EwfImageReader::open(const QString &imagePath, QString &error) {
  close();
  m_lastWarning.clear();
#if defined(FIE_HAS_LIBEWF)
  libewf_error_t *ewfError = nullptr;
  if (libewf_handle_initialize(&m_handle, &ewfError) != 1 || !m_handle) {
    error = "libewf_handle_initialize failed";
    return false;
  }

  const QFileInfo seed(imagePath);
  const auto names = seed.dir().entryList(QDir::Files | QDir::NoDotAndDotDot, QDir::Name);
  QString segmentWarning;
  const QStringList segments = discoverEwfSegments(imagePath, names, &segmentWarning);
  m_lastWarning = segmentWarning;
  std::vector<QByteArray> utf8;
  utf8.reserve(segments.size());
  std::vector<char *> cPaths;
  cPaths.reserve(segments.size());

  for (const auto &s : segments) {
    utf8.push_back(s.toUtf8());
  }
  for (auto &u : utf8) {
    cPaths.push_back(u.data());
  }

  if (libewf_handle_open(m_handle, cPaths.data(), static_cast<int>(cPaths.size()), LIBEWF_OPEN_READ,
                         &ewfError) != 1) {
    error = "libewf_handle_open failed";
    close();
    return false;
  }

  size64_t mediaSize = 0;
  if (libewf_handle_get_media_size(m_handle, &mediaSize, &ewfError) != 1) {
    error = "libewf_handle_get_media_size failed";
    close();
    return false;
  }

  m_path = imagePath;
  m_size = static_cast<quint64>(mediaSize);
  m_isOpen = true;
  return true;
#else
  error = QString("libewf support is unavailable at build time. Cannot open: %1").arg(imagePath);
  return false;
#endif
}

void EwfImageReader::close() {
#if defined(FIE_HAS_LIBEWF)
  libewf_error_t *ewfError = nullptr;
  if (m_handle) {
    libewf_handle_close(m_handle, &ewfError);
    libewf_handle_free(&m_handle, &ewfError);
    m_handle = nullptr;
  }
#endif
  m_isOpen = false;
  m_size = 0;
  m_path.clear();
  m_lastWarning.clear();
}

QByteArray EwfImageReader::read(quint64 offset, quint64 size, QString &error) {
#if defined(FIE_HAS_LIBEWF)
  if (!m_isOpen || !m_handle) {
    error = "EWF image is not open";
    return {};
  }
  if (size == 0) {
    return {};
  }
  if (size > static_cast<quint64>(std::numeric_limits<int>::max())) {
    error = "Requested EWF read exceeds QByteArray size limits";
    return {};
  }
  if (size > static_cast<quint64>(std::numeric_limits<size_t>::max())) {
    error = "Requested EWF read exceeds libewf buffer size limits";
    return {};
  }
  if (offset > static_cast<quint64>(std::numeric_limits<off64_t>::max())) {
    error = "Requested EWF read offset exceeds libewf off64 range";
    return {};
  }
  QByteArray out;
  out.resize(static_cast<int>(size));
  libewf_error_t *ewfError = nullptr;
  const auto readBytes = libewf_handle_read_buffer_at_offset(
      m_handle, reinterpret_cast<uint8_t *>(out.data()), static_cast<size_t>(size), static_cast<off64_t>(offset),
      &ewfError);
  if (readBytes < 0) {
    error = QString("libewf read failed at offset %1").arg(offset);
    return {};
  }
  out.truncate(static_cast<int>(readBytes));
  return out;
#else
  Q_UNUSED(offset)
  Q_UNUSED(size)
  error = "EWF reader is not available in this build";
  return {};
#endif
}

quint64 EwfImageReader::size() const { return m_size; }

bool EwfImageReader::isOpen() const { return m_isOpen; }

QString EwfImageReader::path() const { return m_path; }
QString EwfImageReader::lastWarning() const { return m_lastWarning; }

} // namespace fie::core
