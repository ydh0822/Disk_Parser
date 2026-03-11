#pragma once

#include "ForensicImageExtractor/domain/Models.h"

#include <QJsonObject>

namespace fie::utils {

QJsonObject serializeTimestampSet(const fie::domain::TimestampSet &set);

}
