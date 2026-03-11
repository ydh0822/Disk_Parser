#include "ForensicImageExtractor/utils/TimestampSerializer.h"

namespace fie::utils {

QJsonObject serializeTimestampSet(const fie::domain::TimestampSet &set) {
  QJsonObject obj;
  obj["created"] = set.created ? set.created->toString(Qt::ISODate) : "";
  obj["modified"] = set.modified ? set.modified->toString(Qt::ISODate) : "";
  obj["entry_modified"] = set.entryModified ? set.entryModified->toString(Qt::ISODate) : "";
  obj["accessed"] = set.accessed ? set.accessed->toString(Qt::ISODate) : "";
  return obj;
}

}
