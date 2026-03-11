#pragma once

#include "ForensicImageExtractor/core/IImageReader.h"

struct libewf_handle_t;

namespace fie::core {

class EwfImageReader final : public IImageReader {
public:
  EwfImageReader() = default;
  ~EwfImageReader() override;

  bool open(const QString &imagePath, QString &error) override;
  void close() override;
  QByteArray read(quint64 offset, quint64 size, QString &error) override;
  quint64 size() const override;
  bool isOpen() const override;
  QString path() const override;
  QString lastWarning() const override;

private:
  QString m_path;
  bool m_isOpen{false};
  quint64 m_size{0};
  libewf_handle_t *m_handle{nullptr};
  QString m_lastWarning;
};

} // namespace fie::core
