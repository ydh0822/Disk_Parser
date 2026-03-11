#pragma once

#include <QByteArray>
#include <QString>

namespace fie::utils {

class HashCalculator {
public:
  static QString sha256(const QByteArray &data);
  static QString md5(const QByteArray &data);
};

} // namespace fie::utils
