#include "ForensicImageExtractor/utils/PathUtils.h"

namespace fie::utils {

QString sanitizePathComponent(const QString &input) {
  QString out = input;
  static const QString invalid = "<>:\\|?*\"";
  for (QChar &ch : out) {
    if (invalid.contains(ch) || ch.unicode() < 32) {
      ch = '_';
    }
  }
  if (out.isEmpty()) {
    return "_";
  }
  return out;
}

} // namespace fie::utils
