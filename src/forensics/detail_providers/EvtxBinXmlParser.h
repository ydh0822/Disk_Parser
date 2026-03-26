#pragma once

#include "ForensicImageExtractor/domain/Models.h"

namespace fie::forensics::detail {

bool parseEvtxRecordPayload(const QByteArray &record, domain::ArtifactDetails::EvtxEventEntry &event);

} // namespace fie::forensics::detail
