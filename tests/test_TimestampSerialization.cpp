#include "ForensicImageExtractor/utils/TimestampSerializer.h"

int runTimestampSerializationTests() {
  fie::domain::TimestampSet set;
  set.created = QDateTime::fromString("2024-01-01T00:00:00Z", Qt::ISODate);
  const auto obj = fie::utils::serializeTimestampSet(set);
  return obj["created"].toString().isEmpty() ? 1 : 0;
}
