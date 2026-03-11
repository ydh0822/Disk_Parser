#include "ForensicImageExtractor/utils/HashCalculator.h"

#include <QCryptographicHash>

namespace fie::utils {

QString HashCalculator::sha256(const QByteArray &data) {
  return QString(QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex());
}

QString HashCalculator::md5(const QByteArray &data) {
  return QString(QCryptographicHash::hash(data, QCryptographicHash::Md5).toHex());
}

} // namespace fie::utils
